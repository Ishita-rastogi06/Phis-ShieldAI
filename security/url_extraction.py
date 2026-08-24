"""Canonical extraction, cleanup and deduplication for OCR and email text."""
from __future__ import annotations
import re
from urllib.parse import urlparse

PATTERN = re.compile(r"(?<![\w@])(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)


def extract_urls(text: str) -> list[str]:
    if not text:
        return []
    
    # 1. Rejoin OCR hyphens broken across lines e.g. "amaz0n-verify-\nlogin.ru" -> "amaz0n-verify-login.ru"
    cleaned = re.sub(r'(\w+)-\s*\n\s*(\w+)', r'\1-\2', text)
    
    # 2. Extract standard URLs (http://, https://, www.)
    pattern_http = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)
    
    # 3. Extract domain + path patterns without http:// (e.g. "amaz0n-verify-login.ru/confirm", "fake-invoice-portal.xyz/pay")
    pattern_domain = re.compile(r"\b[a-z0-9\.\-]+\.(?:com|org|net|xyz|ru|tk|ml|cn|biz|info|in|co|gov|edu|site|online|top|live|app|store|tech)/[^\s<>\"']*", re.IGNORECASE)

    # 4. Extract email domain targets e.g. "support@amaz0n-alert-secure.com" -> "https://amaz0n-alert-secure.com"
    pattern_email = re.compile(r"@[a-z0-9\.\-]+\.(?:com|org|net|xyz|ru|tk|ml|cn|biz|info|in|co|gov|edu|site|online|top|live|app|store|tech)\b", re.IGNORECASE)

    raw_candidates = pattern_http.findall(cleaned) + pattern_domain.findall(cleaned)
    for email_domain in pattern_email.findall(cleaned):
        raw_candidates.append("https://" + email_domain.lstrip("@"))

    found, seen = [], set()
    for raw in raw_candidates:
        value = raw.strip("<>\"'(),;")
        value = re.sub(r'[>"\'].*$', '', value)
        value = value.rstrip(".,;:!?)]}\"'")
        if not value.lower().startswith(("http://", "https://")):
            value = "https://" + value
        parsed = urlparse(value)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            continue
        canonical = parsed._replace(scheme=parsed.scheme.lower(), netloc=parsed.netloc.lower()).geturl()
        canonical = canonical[:-1] if canonical.endswith("/") and parsed.path == "/" and not parsed.query else canonical
        if canonical not in seen:
            seen.add(canonical)
            found.append(canonical)
    return found
