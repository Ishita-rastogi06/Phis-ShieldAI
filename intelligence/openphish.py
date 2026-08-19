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
