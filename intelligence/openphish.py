"""Cached correlation against the official OpenPhish community URL feed."""
from __future__ import annotations

import time
from functools import lru_cache
import ssl
import requests
from requests.adapters import HTTPAdapter

from intelligence.contracts import *

FEED_URL = "https://openphish.com/feed.txt"
TTL_SECONDS = 12 * 60 * 60
_cache: tuple[float, set[str]] | None = None


class _OpenPhishSSLAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context()
        kwargs["ssl_context"] = ctx
        return super().init_poolmanager(*args, **kwargs)


def _get_session() -> requests.Session:
    session = requests.Session()
    session.mount("https://", _OpenPhishSSLAdapter())
    return session


def _feed(timeout: float) -> set[str]:
    global _cache
    if _cache and time.monotonic() - _cache[0] < TTL_SECONDS:
        return _cache[1]
    session = _get_session()
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    try:
        response = session.get(FEED_URL, timeout=timeout, headers=headers)
    except requests.exceptions.SSLError:
        response = requests.get(FEED_URL, timeout=timeout, headers=headers)
    response.raise_for_status()
    urls = {line.strip() for line in response.text.splitlines() if line.strip().startswith(("http://", "https://"))}
    _cache = (time.monotonic(), urls)
    return urls


def lookup_url(url: str, timeout: float = 6.0) -> dict:
    import re
    from urllib.parse import urlparse
    from brand_detector import _is_authoritative, detect_brand, has_explicit_phish_indicator
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = parsed.netloc.split(":")[0] if parsed.netloc else parsed.path.split("/")[0] or url

    is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host) or ":" in host)
    path_lower = (parsed.path or "").lower()
    has_login_path = any(p in path_lower for p in ["login", "wp-login", "verify", "signin", "admin", "account", "update", "confirm"])

    is_explicit, p_token = has_explicit_phish_indicator(url)
    is_legit = _is_authoritative(host)
    brand_name, sim = detect_brand(url)
    is_suspicious = (sim >= 70) or is_explicit

    try:
        urls = _feed(timeout)
        feed_size = len(urls)
        
        # 1. Exact URL match in OpenPhish live feed
        if url in urls:
            return result("openphish", AVAILABLE, evidence={"Feed Type": "Live Phishing Feed", "Queried Target": url, "Active Feed Indicators": f"{feed_size:,}"}, malicious=True,
                          strong=True, reason=f"CRITICAL: Exact URL match for '{url}' found in OpenPhish active threat feed!")
        
        # 2. Host match in OpenPhish live feed
        domain_matches = [u for u in urls if host and len(host) > 4 and host in u]
        if domain_matches:
            return result("openphish", AVAILABLE, evidence={"Feed Type": "Live Phishing Feed", "Queried Target": url, "Matched Threat Record": domain_matches[0], "Active Feed Indicators": f"{feed_size:,}"}, malicious=True,
                          strong=True, reason=f"WARNING: Host '{host}' matches active phishing URL record '{domain_matches[0]}' in OpenPhish feed!")

        if is_legit:
            return result("openphish", NO_MATCH, evidence={"Feed Type": "Live Phishing Feed", "Queried Target": url, "Active Feed Indicators": f"{feed_size:,}", "is_legit": True},
                          reason=f"URL '{url}' belongs to a verified trusted brand domain ({host}). Confirmed clean.")

        if is_ip or (is_ip and has_login_path):
            return result("openphish", NO_MATCH, evidence={"Feed Type": "Live Phishing Feed", "Queried Target": url, "Active Feed Indicators": f"{feed_size:,}", "is_suspicious_ip": True},
                          reason=f"UNINDEXED THREAT: Target host is a raw IP address '{host}' with path '{parsed.path}'. 0 matches in OpenPhish feed (IP-based phishing links are unlisted until reported).")

        if is_explicit:
            return result("openphish", NO_MATCH, evidence={"Feed Type": "Live Phishing Feed", "Queried Target": url, "Active Feed Indicators": f"{feed_size:,}", "is_suspicious_brand": True},
                          reason=f"UNINDEXED THREAT: Target domain '{host}' contains explicit phishing indicator '{p_token}'. 0 matches in OpenPhish feed (unlisted until reported).")

        if is_suspicious:
            return result("openphish", NO_MATCH, evidence={"Feed Type": "Live Phishing Feed", "Queried Target": url, "Active Feed Indicators": f"{feed_size:,}", "is_suspicious_brand": True},
                          reason=f"UNLISTED IN FEED: '{host}' exhibits brand impersonation targeting {brand_name.title()}. 0 matches in OpenPhish feed (newly generated links are unlisted until reported).")

        # 3. Clean / No Match in OpenPhish Feed
        return result("openphish", NO_MATCH, evidence={"Feed Type": "Live Phishing Feed", "Queried Target": url, "Active Feed Indicators": f"{feed_size:,}"},
                      reason=f"URL '{url}' verified against OpenPhish live feed ({feed_size:,} active threat records) — 0 exact matches found for '{host}'.")
    except requests.Timeout:
        return result("openphish", TIMEOUT, evidence={"Queried Target": url}, reason=f"OpenPhish feed request timed out while verifying '{host}'.")
    except (requests.RequestException, ValueError) as error:
        return result("openphish", UNAVAILABLE, evidence={"Queried Target": url}, reason=f"OpenPhish provider unavailable for '{host}': {error}")
