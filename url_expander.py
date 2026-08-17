"""URL shortener detection and redirect-chain expansion.

This module provides a single public function, ``expand_url``, which:

1. Detects whether a URL is a known shortener OR a generic redirect
   (any URL that answers with 3xx + Location pointing to a *different* domain).
2. Follows the redirect chain hop-by-hop, with:
   - A per-hop timeout of HOP_TIMEOUT_S (default 5 s).
   - A hard limit of MAX_HOPS (default 5).
   - SSRF validation applied to every resolved Location header before
     following it, so shortener expansion cannot be used as a vector for
     server-side request forgery into internal targets.
3. Returns a structured ``ExpansionResult`` dataclass covering every case:
   - SUCCESS          : chain resolved; final_url is the real destination.
   - NOT_A_SHORTENER  : URL is not a shortener and returned no redirect.
   - SHORTENER_DOWN   : the shortener itself was unreachable / returned 4xx.
   - REDIRECT_LOOP    : same URL appeared twice in the chain.
   - TOO_MANY_HOPS    : chain exceeded MAX_HOPS without resolving.
   - EXPANSION_ERROR  : unexpected network or parsing exception.

The ``redirect_chain`` field always contains every URL visited in order,
including the original input and the final destination.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urljoin, urlparse

import requests

from intelligence.diagnostics import log_scan_stage
from security.url_security import UnsafeURLError, normalise_url

_LOG = logging.getLogger("phishshield.expander")

# ── Constants ─────────────────────────────────────────────────────────────────
MAX_HOPS            = 5       # maximum redirect hops before giving up
HOP_TIMEOUT_S       = 5.0     # per-hop connection + read timeout
GENERIC_DETECT_HOPS = 1       # hops to probe non-listed URLs for redirects

_HEADERS = {
    "User-Agent": "PhishShieldAI/1.0 (+url-expansion)",
    "Accept": "*/*",
}

# Known URL-shortener hostnames (bare registrable domain, no www.)
SHORTENER_DOMAINS: frozenset[str] = frozenset({
    # Major shorteners
    "bit.ly", "bitly.com",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "rb.gy",
    "cutt.ly",
    "shorturl.at",
    "tiny.cc",
    "lnkd.in",
    "urlz.fr",
    "v.gd",
    "trib.al",
    "lc.chat",
    # Additional commonly-abused shorteners
    "bl.ink",
    "clck.ru",
    "db.tt",
    "dlvr.it",
    "fb.me",
    "go2.do",
    "ht.ly",
    "j.mp",
    "mcaf.ee",
    "mktg.ai",
    "po.st",
    "qr.ae",
    "scl.ro",
    "soo.gd",
    "su.pr",
    "tr.im",
    "twit.ac",
    "url4.eu",
    "urlr.me",
    "vurl.com",
    "vzturl.com",
    "x.co",
    "yourls.org",
    "za.gl",
    "zi.pe",
    "zpr.io",
})


class ExpansionStatus(str, Enum):
    SUCCESS            = "SUCCESS"
    NOT_A_SHORTENER    = "NOT_A_SHORTENER"
    SHORTENER_DOWN     = "SHORTENER_DOWN"
    REDIRECT_LOOP      = "REDIRECT_LOOP"
    TOO_MANY_HOPS      = "TOO_MANY_HOPS"
    EXPANSION_ERROR    = "EXPANSION_ERROR"


@dataclass
class ExpansionResult:
    status:         ExpansionStatus
    original_url:   str
    final_url:      str                   # equals original_url when not expanded
    redirect_chain: list[str] = field(default_factory=list)
    hops:           int = 0
    message:        str = ""
    elapsed_s:      float = 0.0

    @property
    def was_expanded(self) -> bool:
        """True when the final URL differs from the original input."""
        return self.status == ExpansionStatus.SUCCESS and self.final_url != self.original_url


def _registrable_host(url: str) -> str:
    """Return the bare hostname (lowercase) from a URL string."""
    try:
        return (urlparse(url).hostname or "").lower().lstrip("www.")
    except Exception:
        return ""


def _is_known_shortener(url: str) -> bool:
    host = _registrable_host(url)
    # Exact match OR ends with .shortener_domain (e.g. custom.bit.ly)
    return host in SHORTENER_DOMAINS or any(
        host.endswith("." + d) for d in SHORTENER_DOMAINS
    )


def expand_url(url: str, *, force: bool = False) -> ExpansionResult:
    """Follow the redirect chain for *url* and return an ``ExpansionResult``.

    Args:
        url:   The URL to expand (may or may not be a shortener).
        force: If True, always probe for redirects even for non-listed domains.
               Normally only known shorteners and URLs that produce a 3xx on
               the first request are expanded.

    Returns:
        ExpansionResult describing the outcome.  ``redirect_chain`` always
        includes the input URL as the first element.
    """
    t0 = time.perf_counter()
    known = _is_known_shortener(url)

    log_scan_stage(
        "expander_start",
        input_url=url,
        known_shortener=known,
        force=force,
    )

    # Skip expansion immediately for non-shortener URLs unless forced.
    # We will still do one probe hop to catch generic redirectors.
    if not known and not force:
        result = _probe_and_expand(url, max_hops=GENERIC_DETECT_HOPS)
        elapsed = round(time.perf_counter() - t0, 3)
        result.elapsed_s = elapsed
        log_scan_stage(
            "expander_done",
            input_url=url,
            status=result.status.value,
            final_url=result.final_url,
            hops=result.hops,
            elapsed_s=elapsed,
        )
        return result

    # Full expansion for known shorteners (or forced).
    result = _probe_and_expand(url, max_hops=MAX_HOPS)
    elapsed = round(time.perf_counter() - t0, 3)
    result.elapsed_s = elapsed
    log_scan_stage(
        "expander_done",
        input_url=url,
        status=result.status.value,
        final_url=result.final_url,
        hops=result.hops,
        elapsed_s=elapsed,
    )
    return result


def _probe_and_expand(url: str, *, max_hops: int) -> ExpansionResult:
    """Core hop-follower.  Validates every Location via SSRF guard before use."""
    chain: list[str] = [url]
    current = url
    seen: set[str] = {url}

    for hop in range(1, max_hops + 1):
        # Validate the URL we are about to fetch through the SSRF guard.
        try:
            safe_current = normalise_url(current)
        except UnsafeURLError as exc:
            _LOG.warning("expander: SSRF block at hop %d url=%r: %s", hop, current, exc)
            return ExpansionResult(
                status=ExpansionStatus.EXPANSION_ERROR,
                original_url=url,
                final_url=chain[-1],
                redirect_chain=chain,
                hops=hop - 1,
                message=f"SSRF validation blocked hop {hop}: {exc}",
            )

        try:
            resp = requests.head(
                safe_current,
                headers=_HEADERS,
                timeout=HOP_TIMEOUT_S,
                allow_redirects=False,
                stream=False,
            )
            # Some servers don't honour HEAD; fall back to GET with no body.
            if resp.status_code == 405:
                resp = requests.get(
                    safe_current,
                    headers=_HEADERS,
                    timeout=HOP_TIMEOUT_S,
                    allow_redirects=False,
                    stream=True,
                )
                # Discard the body immediately — we only want headers.
                resp.close()
        except requests.exceptions.ConnectionError as exc:
            msg = f"Connection error at hop {hop} ({current}): {exc}"
            _LOG.warning("expander: %s", msg)
            # Only treat hop-1 failure as SHORTENER_DOWN for *known* shortener
            # domains.  For generic probe hops on non-shortener URLs, a
            # connection failure means the site is unreachable — return
            # EXPANSION_ERROR so the pipeline continues with the original URL
            # rather than treating the scan as a "shortener down" event.
            is_shortener_hop = _is_known_shortener(url)
            status = (
                ExpansionStatus.SHORTENER_DOWN
                if hop == 1 and is_shortener_hop
                else ExpansionStatus.EXPANSION_ERROR
            )
            return ExpansionResult(
                status=status,
                original_url=url,
                final_url=chain[-1],
                redirect_chain=chain,
                hops=hop - 1,
                message=msg,
            )
        except requests.exceptions.Timeout:
            msg = f"Timeout at hop {hop} ({current})"
            _LOG.warning("expander: %s", msg)
            is_shortener_hop = _is_known_shortener(url)
            status = (
                ExpansionStatus.SHORTENER_DOWN
                if hop == 1 and is_shortener_hop
                else ExpansionStatus.EXPANSION_ERROR
            )
            return ExpansionResult(
                status=status,
                original_url=url,
                final_url=chain[-1],
                redirect_chain=chain,
                hops=hop - 1,
                message=msg,
            )
        except requests.exceptions.RequestException as exc:
            msg = f"Request error at hop {hop}: {exc}"
            _LOG.warning("expander: %s", msg)
            return ExpansionResult(
                status=ExpansionStatus.EXPANSION_ERROR,
                original_url=url,
                final_url=chain[-1],
                redirect_chain=chain,
                hops=hop - 1,
                message=msg,
            )

        _LOG.debug(
            "expander hop=%d status=%d url=%r location=%r",
            hop, resp.status_code,
            current,
            resp.headers.get("Location"),
        )

        # Non-redirect: this is the final destination.
        if resp.status_code not in (301, 302, 303, 307, 308):
            # First hop returned non-redirect and URL is not a listed shortener
            if hop == 1 and current == url and not _is_known_shortener(url):
                return ExpansionResult(
                    status=ExpansionStatus.NOT_A_SHORTENER,
                    original_url=url,
                    final_url=current,
                    redirect_chain=chain,
                    hops=0,
                )
            # 4xx/5xx on hop 1 → shortener itself is down/expired (known shorteners only)
            if hop == 1 and resp.status_code >= 400 and _is_known_shortener(url):
                return ExpansionResult(
                    status=ExpansionStatus.SHORTENER_DOWN,
                    original_url=url,
                    final_url=current,
                    redirect_chain=chain,
                    hops=0,
                    message=f"Shortener returned HTTP {resp.status_code}",
                )
            # Otherwise we've successfully reached the destination
            return ExpansionResult(
                status=ExpansionStatus.SUCCESS,
                original_url=url,
                final_url=current,
                redirect_chain=chain,
                hops=hop - 1,
            )

        # Got a redirect — resolve the Location header.
        location = resp.headers.get("Location", "").strip()
        if not location:
            return ExpansionResult(
                status=ExpansionStatus.EXPANSION_ERROR,
                original_url=url,
                final_url=current,
                redirect_chain=chain,
                hops=hop - 1,
                message=f"Redirect at hop {hop} had empty Location header",
            )

        # Resolve relative Location against current URL.
        next_url = urljoin(current, location)

        # Loop detection.
        if next_url in seen:
            return ExpansionResult(
                status=ExpansionStatus.REDIRECT_LOOP,
                original_url=url,
                final_url=current,
                redirect_chain=chain,
                hops=hop,
                message=f"Redirect loop detected: {next_url} already visited",
            )

        seen.add(next_url)
        chain.append(next_url)
        current = next_url

    # Exhausted hop budget.
    return ExpansionResult(
        status=ExpansionStatus.TOO_MANY_HOPS,
        original_url=url,
        final_url=current,
        redirect_chain=chain,
        hops=max_hops,
        message=f"Redirect chain exceeded {max_hops} hops",
    )
