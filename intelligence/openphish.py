"""Cached correlation against the official OpenPhish community URL feed."""
from __future__ import annotations

import time
from functools import lru_cache
import requests

from intelligence.contracts import *

FEED_URL = "https://openphish.com/feed.txt"
TTL_SECONDS = 12 * 60 * 60
_cache: tuple[float, set[str]] | None = None


def _feed(timeout: float) -> set[str]:
    global _cache
    if _cache and time.monotonic() - _cache[0] < TTL_SECONDS:
        return _cache[1]
    response = requests.get(FEED_URL, timeout=timeout, headers={"User-Agent": "PhishShieldAI/1.0"})
    response.raise_for_status()
    urls = {line.strip() for line in response.text.splitlines() if line.strip().startswith(("http://", "https://"))}
    _cache = (time.monotonic(), urls)
    return urls


def lookup_url(url: str, timeout: float = 6.0) -> dict:
    try:
        urls = _feed(timeout)
        if url in urls:
            return result("openphish", AVAILABLE, evidence={"feed": "community", "matched_url": url}, malicious=True,
                          strong=True, reason="Exact OpenPhish community-feed match")
        return result("openphish", NO_MATCH, reason="No exact OpenPhish community-feed match")
    except requests.Timeout:
        return result("openphish", TIMEOUT, reason="OpenPhish feed request timed out")
    except (requests.RequestException, ValueError) as error:
        return result("openphish", UNAVAILABLE, reason=str(error))
