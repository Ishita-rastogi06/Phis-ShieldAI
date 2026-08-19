"""Privacy-conscious urlscan.io existing-scan lookup.

Never submits URLs for new scans — only searches existing results.
A 10-minute result cache and exponential backoff on HTTP 429 prevent burning
free-tier quota during repeated scans or live demos.
"""
from __future__ import annotations

import os
import ssl
import requests
from requests.adapters import HTTPAdapter

from intelligence.contracts import *
from intelligence.diagnostics import log_provider_http, log_provider_result
from intelligence.provider_cache import (
    cache_get, cache_set, is_rate_limited, record_rate_limit, record_success,
)


class _UrlscanSSLAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context()
        kwargs["ssl_context"] = ctx
        return super().init_poolmanager(*args, **kwargs)


def _get_session() -> requests.Session:
    session = requests.Session()
    session.mount("https://", _UrlscanSSLAdapter())
    return session


def lookup_url(url: str, timeout: float = 6.0) -> dict:
    # ── Cache hit ─────────────────────────────────────────────────────────────
    cached = cache_get("urlscan", url)
    if cached is not None:
        log_provider_result("urlscan", url, {**cached, "reason": (cached.get("reason") or "") + " [cache hit]"})
        return cached

    # ── Backoff check ─────────────────────────────────────────────────────────
    limited, limited_result = is_rate_limited("urlscan")
    if limited:
        log_provider_result("urlscan", url, limited_result)
        return limited_result

    # ── Key check ─────────────────────────────────────────────────────────────
    key = os.getenv("URLSCAN_API_KEY", "").strip()
    if not key:
        outcome = result("urlscan", NOT_CONFIGURED, reason="URLSCAN_API_KEY is not configured")
        log_provider_result("urlscan", url, outcome)
        return outcome

    # ── Live request ──────────────────────────────────────────────────────────
    try:
        try:
            response = requests.get(
                "https://urlscan.io/api/v1/search/",
                params={"q": f'task.url.keyword:"{url}"', "size": 3},
                headers={
                    "API-Key": key,
                    "Accept": "application/json",
                    "User-Agent": "PhishShieldAI/1.0",
                },
                timeout=timeout,
            )
        except requests.exceptions.SSLError:
            session = _get_session()
            response = session.get(
                "https://urlscan.io/api/v1/search/",
                params={"q": f'task.url.keyword:"{url}"', "size": 3},
                headers={
                    "API-Key": key,
                    "Accept": "application/json",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                },
                timeout=timeout,
            )
        log_provider_http("urlscan", url, response.status_code)

        if response.status_code == 429:
            outcome = result("urlscan", RATE_LIMITED,
                             reason="urlscan rate limit reached — backing off")
            record_rate_limit("urlscan", outcome)
            log_provider_result("urlscan", url, outcome)
            return outcome
        elif response.status_code in (401, 403):
            outcome = result("urlscan", UNAVAILABLE,
                             reason="urlscan authentication rejected (check URLSCAN_API_KEY)")
            log_provider_result("urlscan", url, outcome)
            return outcome

        response.raise_for_status()
        matches = response.json().get("results", [])[:3]

        if not matches:
            outcome = result("urlscan", NO_MATCH, reason="No existing urlscan result for this URL")
            cache_set("urlscan", url, outcome)
            log_provider_result("urlscan", url, outcome)
            return outcome

        evidence = [
            {
                "id":   item.get("_id"),
                "page": item.get("page", {}),
                "task": item.get("task", {}),
                "stats": item.get("stats", {}),
            }
            for item in matches
        ]
        outcome = result("urlscan", AVAILABLE,
                         evidence={"matches": evidence},
                         reason=f"Found {len(evidence)} existing urlscan result(s)")
        record_success("urlscan")
        cache_set("urlscan", url, outcome)

    except requests.Timeout:
        outcome = result("urlscan", TIMEOUT, reason="urlscan request timed out")
    except (requests.RequestException, ValueError) as error:
        outcome = result("urlscan", UNAVAILABLE, reason=str(error))

    log_provider_result("urlscan", url, outcome)
    return outcome
