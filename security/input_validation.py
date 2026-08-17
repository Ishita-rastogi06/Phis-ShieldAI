import re
from urllib.parse import urlparse


def validate_url(url: str) -> bool:
    if not isinstance(url, str):
        return False

    url = url.strip()
    if not url:
        return False

    parsed = urlparse(url if "://" in url else "https://" + url)
    if not parsed.netloc:
        return False

    host = parsed.netloc.lower()
    if " " in host or ".." in host:
        return False

    if host.count(".") == 0:
        return False

    return True


def validate_text(text: str) -> bool:
    if not isinstance(text, str):
        return False
    return bool(text.strip())
