"""SSRF controls for every outbound URL fetch made by PhishShield.

Every decision (pass or block) is logged to 'phishshield.ssrf' so the
diagnostic pipeline can trace exactly which validation rule fires for each
URL — or confirm that no rule fired and the URL passed cleanly through to
the provider calls.
"""
from __future__ import annotations

import ipaddress
import logging
import socket
import sys
from urllib.parse import urlparse

SAFE_SCHEMES = {"http", "https"}

# Bootstrap a visible logger the same way diagnostics.py does — stderr output
# is always present even when no root handler is configured.
_SSRF_LOGGER = logging.getLogger("phishshield.ssrf")
if not _SSRF_LOGGER.handlers and not logging.root.handlers:
    _h = logging.StreamHandler(sys.stderr)
    _h.setFormatter(logging.Formatter("[PhishShield:SSRF] %(levelname)s %(message)s"))
    _SSRF_LOGGER.addHandler(_h)
    _SSRF_LOGGER.setLevel(logging.DEBUG)


class UnsafeURLError(ValueError):
    pass


def normalise_url(value: str) -> str:
    """Normalise *value* to an absolute http/https URL and run SSRF guards.

    Every decision — pass or block — is logged with the rule name so callers
    can confirm that legitimate public domains are never short-circuited.
    """
    raw = str(value or "").strip().rstrip(".,;:!?) }\"'").rstrip()

    # ── rule: scheme prepend ─────────────────────────────────────────────────
    if raw.lower().startswith("www."):
        raw = "https://" + raw
        _SSRF_LOGGER.debug("ssrf_rule=scheme_prepend input=%r result=%r", value, raw)
    elif "://" not in raw:
        raw = "https://" + raw
        _SSRF_LOGGER.debug("ssrf_rule=scheme_prepend input=%r result=%r", value, raw)

    try:
        parsed = urlparse(raw)
    except ValueError as error:
        _SSRF_LOGGER.warning("ssrf_rule=malformed_url input=%r error=%r — BLOCKED", value, str(error))
        raise UnsafeURLError(f"Malformed URL: {error}") from error

    # ── rule: scheme allowlist ───────────────────────────────────────────────
    if parsed.scheme.lower() not in SAFE_SCHEMES:
        _SSRF_LOGGER.warning(
            "ssrf_rule=disallowed_scheme input=%r scheme=%r allowed=%r — BLOCKED",
            value, parsed.scheme, sorted(SAFE_SCHEMES),
        )
        raise UnsafeURLError(
            "Only public http/https URLs without embedded credentials are allowed."
        )

    # ── rule: missing hostname ───────────────────────────────────────────────
    if not parsed.hostname:
        _SSRF_LOGGER.warning("ssrf_rule=no_hostname input=%r — BLOCKED", value)
        raise UnsafeURLError(
            "Only public http/https URLs without embedded credentials are allowed."
        )

    # ── rule: embedded credentials ──────────────────────────────────────────
    if parsed.username or parsed.password:
        _SSRF_LOGGER.warning(
            "ssrf_rule=embedded_credentials input=%r — BLOCKED", value
        )
        raise UnsafeURLError(
            "Only public http/https URLs without embedded credentials are allowed."
        )

    # ── host-level validation (may raise UnsafeURLError) ────────────────────
    _validate_host(parsed.hostname)

    _SSRF_LOGGER.info("ssrf_rule=passed input=%r normalised=%r", value, parsed.geturl())
    return parsed.geturl()


def _private(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    )


def _validate_host(host: str) -> None:
    """Block private/loopback/internal targets; log the rule that fired."""

    # ── rule: raw IP literal ─────────────────────────────────────────────────
    try:
        stripped = host.strip("[]")
        if _private(stripped):
            _SSRF_LOGGER.warning(
                "ssrf_rule=private_ip host=%r — BLOCKED", host
            )
            raise UnsafeURLError(
                "Private, loopback, link-local, or reserved targets are blocked."
            )
        # Public IP literal — log and allow.
        _SSRF_LOGGER.info("ssrf_rule=public_ip host=%r — allowed", host)
        return
    except ValueError:
        pass  # Not an IP literal — fall through to hostname checks.

    # ── rule: localhost hostname ─────────────────────────────────────────────
    host_lower = host.lower()
    if (
        host_lower in {"localhost", "localhost.localdomain"}
        or host_lower.endswith(".localhost")
    ):
        _SSRF_LOGGER.warning("ssrf_rule=localhost host=%r — BLOCKED", host)
        raise UnsafeURLError("Localhost targets are blocked.")

    # ── rule: DNS resolution ─────────────────────────────────────────────────
    try:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        }
    except socket.gaierror as error:
        _SSRF_LOGGER.warning(
            "ssrf_rule=dns_resolution_failed host=%r error=%r — BLOCKED",
            host, str(error),
        )
        raise UnsafeURLError(f"DNS resolution failed: {error}") from error

    if not addresses:
        _SSRF_LOGGER.warning("ssrf_rule=dns_no_addresses host=%r — BLOCKED", host)
        raise UnsafeURLError("DNS resolution returned no addresses.")

    # ── rule: DNS-resolved private address ──────────────────────────────────
    private_hits = [a for a in addresses if _private(a)]
    if private_hits:
        _SSRF_LOGGER.warning(
            "ssrf_rule=dns_resolves_to_private host=%r resolved=%r private_hits=%r — BLOCKED",
            host, sorted(addresses), private_hits,
        )
        raise UnsafeURLError(
            "DNS resolved to a private, loopback, link-local, or reserved target."
        )

    _SSRF_LOGGER.info(
        "ssrf_rule=dns_passed host=%r resolved_addresses=%r — allowed",
        host, sorted(addresses),
    )


def validate_redirect(url: str) -> str:
    """Validate each redirect target before a caller follows it."""
    return normalise_url(url)
