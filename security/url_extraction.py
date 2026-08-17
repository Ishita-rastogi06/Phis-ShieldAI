"""Canonical extraction, cleanup and deduplication for OCR and email text."""
from __future__ import annotations
import re
from urllib.parse import urlparse

PATTERN = re.compile(r"(?<![\w@])(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)


def extract_urls(text: str) -> list[str]:
    found, seen = [], set()
    for raw in PATTERN.findall(text or ""):
        value = raw.rstrip(".,;:!?)]}\"'")
        if value.lower().startswith("www."): value = "https://" + value
        parsed = urlparse(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname: continue
        # Keep extraction offline: do not resolve DNS merely to deduplicate
        # text.  Host casing and a trailing root slash are normalized here;
        # the canonical URL pipeline performs security validation later.
        canonical = parsed._replace(scheme=parsed.scheme.lower(), netloc=parsed.netloc.lower()).geturl()
        canonical = canonical[:-1] if canonical.endswith("/") and parsed.path == "/" and not parsed.query else canonical
        if canonical not in seen:
            seen.add(canonical); found.append(canonical)
    return found
