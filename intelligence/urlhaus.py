"""URLhaus URL intelligence adapter (lookup-only).

A 10-minute result cache and exponential backoff on HTTP 429 prevent burning
free-tier quota during repeated scans or live demos.
"""
from __future__ import annotations

import os
import requests

from intelligence.contracts import *
from intelligence.diagnostics import log_provider_http, log_provider_result
from intelligence.provider_cache import (
    cache_get, cache_set, is_rate_limited, record_rate_limit, record_success,
)

API = "https://urlhaus-api.abuse.ch/v1/url/"


def lookup_url(url: str, timeout: float = 6.0) -> dict:
    # ── Cache hit ─────────────────────────────────────────────────────────────
    cached = cache_get("urlhaus", url)
    if cached is not None:
        log_provider_result("urlhaus", url, {**cached, "reason": (cached.get("reason") or "") + " [cache hit]"})
        return cached

    # ── Backoff check ─────────────────────────────────────────────────────────
    limited, limited_result = is_rate_limited("urlhaus")
    if limited:
        log_provider_result("urlhaus", url, limited_result)
        return limited_result

    # ── Key check ─────────────────────────────────────────────────────────────
    key = os.getenv("URLHAUS_AUTH_KEY", "").strip()
    if not key:
        outcome = result("urlhaus", NOT_CONFIGURED, reason="URLHAUS_AUTH_KEY is not configured")
        log_provider_result("urlhaus", url, outcome)
        return outcome

    # ── Live request ──────────────────────────────────────────────────────────
    try:
        response = requests.post(
            API,
            data={"url": url},
            headers={"Auth-Key": key, "User-Agent": "PhishShieldAI/1.0"},
            timeout=timeout,
        )
        log_provider_http("urlhaus", url, response.status_code)

        if response.status_code == 429:
            outcome = result("urlhaus", RATE_LIMITED,
                             reason="URLhaus rate limit reached — backing off")
            record_rate_limit("urlhaus", outcome)
            log_provider_result("urlhaus", url, outcome)
            return outcome
        elif response.status_code in (401, 403):
            outcome = result("urlhaus", UNAVAILABLE,
                             reason="URLhaus authentication rejected (check URLHAUS_AUTH_KEY)")
            log_provider_result("urlhaus", url, outcome)
            return outcome

        response.raise_for_status()
        data = response.json()

        query_status = data.get("query_status", "")
        if query_status in {"no_results", "invalid_url"}:
            outcome = result("urlhaus", NO_MATCH, reason="No URLhaus record for this URL")
            cache_set("urlhaus", url, outcome)
            log_provider_result("urlhaus", url, outcome)
            return outcome
        elif query_status != "ok":
            outcome = result("urlhaus", UNAVAILABLE,
                             reason=f"Unexpected URLhaus query_status: '{query_status}'")
            log_provider_result("urlhaus", url, outcome)
            return outcome

        evidence = {k: data.get(k) for k in
                    ("id", "url", "url_status", "threat", "tags",
                     "date_added", "last_online", "host")}
        active = data.get("url_status") == "online"
        outcome = result(
            "urlhaus", AVAILABLE,
            evidence=evidence,
            malicious=True,
            strong=active,
            reason=("Active malware-distribution URLhaus record"
                    if active else "URLhaus malware URL record (offline)"),
        )
        record_success("urlhaus")
        cache_set("urlhaus", url, outcome)

    except requests.Timeout:
        outcome = result("urlhaus", TIMEOUT, reason="URLhaus request timed out")
    except (requests.RequestException, ValueError) as error:
        outcome = result("urlhaus", UNAVAILABLE, reason=str(error))

    log_provider_result("urlhaus", url, outcome)
    return outcome
