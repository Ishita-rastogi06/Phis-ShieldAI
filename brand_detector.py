"""Conservative brand-impersonation detection for registrable-domain evidence."""
from __future__ import annotations

import re
from urllib.parse import urlparse

from rapidfuzz import fuzz
from security.tldextract_config import offline_extractor

_EXTRACT = offline_extractor()
BRAND_DOMAINS = {
    "amazon": {"amazon.com", "amazon.in", "amazonaws.com"}, "google": {"google.com", "gmail.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com"}, "apple": {"apple.com", "icloud.com"},
    "paypal": {"paypal.com"}, "netflix": {"netflix.com"}, "github": {"github.com"},
    "facebook": {"facebook.com", "instagram.com", "meta.com"}, "stripe": {"stripe.com"},
    "linkedin": {"linkedin.com"}, "sbi": {"sbi.co.in"}, "hdfc": {"hdfcbank.com"},
    "wikipedia": {"wikipedia.org"},
}
AUTHORITATIVE_DOMAINS = {domain for domains in BRAND_DOMAINS.values() for domain in domains} | {
    "stackoverflow.com", "stackexchange.com", "reddit.com", "bbc.com", "bbc.co.uk",
    "reuters.com", "cloudflare.com", "pypi.org", "npmjs.com", "example.com",
}
GENERIC_TOKENS = {"login", "secure", "account", "verify", "update", "support", "mail", "cloud", "service", "official", "signin", "sign", "www", "auth", "portal", "online"}


def _host(url: str) -> str:
    return (urlparse(url if "://" in url else f"https://{url}").hostname or "").lower().strip(".")


def _registrable_domain(host: str) -> str:
    parts = _EXTRACT(host)
    return ".".join(part for part in (parts.domain, parts.suffix) if part)


def _is_authoritative(netloc: str) -> bool:
    host = _host(netloc)
    domain = _registrable_domain(host)
    return any(domain == known or domain.endswith("." + known) for known in AUTHORITATIVE_DOMAINS)


def _tokens(host: str) -> set[str]:
    return {token for token in re.split(r"[^a-z0-9]+", host) if token and token not in GENERIC_TOKENS}


def detect_brand(url: str) -> tuple[str, int]:
    """Return a brand only with direct hostname evidence; never guess from generic fuzziness."""
    host = _host(url)
    domain = _registrable_domain(host)
    if not host or _is_authoritative(host):
        return "Unknown", 0
    label = _EXTRACT(host).domain.lower()
    meaningful = _tokens(host)
    candidates: list[tuple[str, int]] = []
    for brand, domains in BRAND_DOMAINS.items():
        # Direct brand token on a non-authoritative registrable domain is strong evidence.
        if brand in meaningful or brand in label:
            candidates.append((brand, 95))
            continue
        # Typo evidence compares only the registrable label, never arbitrary URL text.
        typo_scores = [fuzz.ratio(brand, token) for token in meaningful]
        ratio = max(typo_scores, default=0)
        if len(brand) >= 5 and ratio >= 82:
            candidates.append((brand, int(ratio)))
    if not candidates:
        return "Unknown", 0
    brand, score = max(candidates, key=lambda item: item[1])
    return brand, score
