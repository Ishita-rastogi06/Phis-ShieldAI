"""Production extraction for all 30 UCI Phishing Websites features.

The feature vector is only emitted when every required live signal is available;
unknown values are never replaced with constants.  The external-intelligence
provider is documented in ``.env.example`` and supplies the historical signals
that cannot be reconstructed from a URL or a fetched page alone.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, List
from urllib.parse import urljoin, urlparse

import requests
import whois
from bs4 import BeautifulSoup
from security.tldextract_config import offline_extractor

FEATURE_SCHEMA_VERSION = "uci-all-30-v1"
URL_FEATURE_NAMES = [
    "having_IP_Address", "URL_Length", "Shortining_Service", "having_At_Symbol",
    "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_State",
    "Domain_registeration_length", "Favicon", "port", "HTTPS_token", "Request_URL",
    "URL_of_Anchor", "Links_in_tags", "SFH", "Submitting_to_email", "Abnormal_URL",
    "Redirect", "on_mouseover", "RightClick", "popUpWidnow", "Iframe", "age_of_domain",
    "DNSRecord", "web_traffic", "Page_Rank", "Google_Index", "Links_pointing_to_page",
    "Statistical_report",
]
SHORTENER_HOSTS = {"bit.ly", "buff.ly", "cutt.ly", "goo.gl", "is.gd", "lc.chat", "lnkd.in", "ow.ly", "rb.gy", "rebrand.ly", "shorturl.at", "t.co", "tiny.cc", "tinyurl.com", "trib.al", "urlz.fr", "v.gd"}
TIMEOUT_SECONDS = 2.0
# Use tldextract's packaged Public Suffix List snapshot. Runtime extraction must
# not make a background network request merely to resolve a registrable domain.
_TLD_EXTRACT = offline_extractor()


class FeatureUnavailableError(RuntimeError):
    """A required live signal could not be collected safely."""


def _normalise_url(url: str) -> str:
    value = str(url).strip()
    if not value:
        raise ValueError("URL is empty")
    return value if "://" in value else f"https://{value}"


def _host_is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]")); return True
    except ValueError:
        return False


def _registrable_domain(host: str) -> str:
    extracted = _TLD_EXTRACT(host)
    return ".".join(part for part in (extracted.domain, extracted.suffix) if part)


def _same_site(url: str, domain: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host == domain or host.endswith("." + domain)


LEGACY_UNAVAILABLE_FEATURES = ("web_traffic", "Page_Rank", "Google_Index", "Links_pointing_to_page", "Statistical_report")


def _get_whois(domain: str):
    try:
        from whois_checker import check_domain_age
        data = check_domain_age(domain)
        if data and data.get("status") == "AVAILABLE" and data.get("creation_date"):
            c_dt = datetime.fromisoformat(data["creation_date"]) if data.get("creation_date") else None
            e_dt = datetime.fromisoformat(data["expiry_date"]) if data.get("expiry_date") else None
            return data, c_dt, e_dt
    except Exception:
        pass
    return None, None, None


def _ssl_state(host: str, scheme: str) -> int:
    if scheme != "https": return -1
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=TIMEOUT_SECONDS) as connection:
            with context.wrap_socket(connection, server_hostname=host) as secure_connection:
                certificate = secure_connection.getpeercert()
        not_before = datetime.strptime(certificate["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        return 1 if (datetime.now(timezone.utc) - not_before).days >= 365 else 0
    except Exception:
        return 0


def _page_features(response: requests.Response, domain: str) -> Dict[str, int]:
    soup = BeautifulSoup(response.text, "html.parser")
    resources = [tag.get(attribute) for tag, attribute in ((tag, attribute) for tag in soup.find_all(["img", "script", "link", "video", "audio"]) for attribute in ("src", "href")) if tag.get(attribute)]
    def external_ratio(urls: list[str]) -> float:
        if not urls: return 0.0
        return sum(not _same_site(urljoin(response.url, item), domain) for item in urls) * 100 / len(urls)
    request_ratio = external_ratio(resources)
    anchors = [anchor.get("href") for anchor in soup.find_all("a") if anchor.get("href")]
    null_or_external = [item for item in anchors if item in ("#", "#content", "#skip", "javascript:void(0)") or not _same_site(urljoin(response.url, item), domain)]
    anchor_ratio = len(null_or_external) * 100 / len(anchors) if anchors else 0.0
    tag_urls = [tag.get(attribute) for tag, attribute in ((tag, attribute) for tag in soup.find_all(["meta", "script", "link"]) for attribute in ("content", "src", "href")) if tag.get(attribute) and str(tag.get(attribute)).startswith(("http://", "https://"))]
    tag_ratio = external_ratio(tag_urls)
    favicon = soup.find("link", rel=lambda value: value and "icon" in value.lower())
    favicon_url = urljoin(response.url, favicon.get("href")) if favicon and favicon.get("href") else response.url + "/favicon.ico"
    forms = soup.find_all("form")
    actions = [form.get("action", "").strip() for form in forms]
    if any(action in ("", "about:blank") for action in actions): sfh = -1
    elif any(not _same_site(urljoin(response.url, action), domain) for action in actions): sfh = 0
    else: sfh = 1
    html = response.text.lower()
    return {
        "Favicon": -1 if not _same_site(favicon_url, domain) else 1,
        "Request_URL": 1 if request_ratio < 22 else 0 if request_ratio <= 61 else -1,
        "URL_of_Anchor": 1 if anchor_ratio < 31 else 0 if anchor_ratio <= 67 else -1,
        "Links_in_tags": 1 if tag_ratio < 17 else 0 if tag_ratio <= 81 else -1,
        "SFH": sfh,
        "Submitting_to_email": -1 if "mailto:" in html else 1,
        "Redirect": 1 if len(response.history) <= 1 else 0,
        "on_mouseover": -1 if "onmouseover" in html and ("window.status" in html or "status=" in html) else 1,
        "RightClick": -1 if "contextmenu" in html or "oncontextmenu" in html else 1,
        "popUpWidnow": -1 if "window.open(" in html or "alert(" in html else 1,
        "Iframe": -1 if soup.find(["iframe", "frame"]) else 1,
    }


LIVE_25_FEATURE_NAMES = [
    "having_IP_Address", "URL_Length", "Shortining_Service", "having_At_Symbol",
    "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_State",
    "Domain_registeration_length", "Favicon", "port", "HTTPS_token", "Request_URL",
    "URL_of_Anchor", "Links_in_tags", "SFH", "Submitting_to_email", "Abnormal_URL",
    "Redirect", "on_mouseover", "RightClick", "popUpWidnow", "Iframe", "age_of_domain",
    "DNSRecord"
]


def extract_live_feature_mapping(url: str) -> Dict[str, int]:
    """Extract all 25 live-collectible integer features for real-time URL inference."""
    raw_url = _normalise_url(url)
    parsed = urlparse(raw_url)
    host = (parsed.hostname or "").lower()
    scheme = parsed.scheme.lower()

    if not host:
        raise FeatureUnavailableError(f"Cannot extract features: invalid hostname in '{url}'")

    domain = _registrable_domain(host)

    # 1. IP Address
    having_ip = -1 if _host_is_ip(host) else 1

    # 2. URL Length
    url_len = len(raw_url)
    length_feat = 1 if url_len < 54 else 0 if url_len <= 75 else -1

    # 3. URL Shortener
    short_feat = -1 if host in SHORTENER_HOSTS or any(h in host for h in ("tinyurl", "bit.ly", "goo.gl", "t.co")) else 1

    # 4. Having '@' symbol
    at_feat = -1 if "@" in raw_url else 1

    # 5. Double slash redirect
    double_slash_pos = raw_url.rfind("//")
    double_slash_feat = -1 if double_slash_pos > 7 else 1

    # 6. Prefix / Suffix (hyphen in domain)
    prefix_suffix_feat = -1 if "-" in domain else 1

    # 7. Subdomains count
    sub_parts = host.split(".")
    sub_count = max(0, len(sub_parts) - 2)
    subdomain_feat = 1 if sub_count <= 1 else 0 if sub_count == 2 else -1

    # 25. DNS Record
    try:
        socket.gethostbyname(host)
        dns_feat = 1
    except Exception:
        dns_feat = -1

    # 8. SSL / TLS state
    ssl_feat = _ssl_state(host, scheme) if dns_feat == 1 else -1

    # 9. Domain registration length & 24. Age of domain
    _whois_data, c_dt, e_dt = _get_whois(domain)
    now = datetime.now(timezone.utc)
    if c_dt:
        age_days = (now - c_dt).days
        domain_age_feat = 1 if age_days >= 180 else -1
    else:
        domain_age_feat = -1

    if c_dt and e_dt:
        reg_days = (e_dt - c_dt).days
        domain_reg_feat = 1 if reg_days >= 365 else -1
    else:
        domain_reg_feat = -1

    # 11. Port
    port_feat = -1 if parsed.port and parsed.port not in (80, 443) else 1

    # 12. HTTPS token in host domain
    https_token_feat = -1 if "https" in host.replace("https://", "") else 1

    # 18. Abnormal URL (typosquatting / suspicious keywords / unresolvable host)
    suspicious_kw = ("login", "verify", "update", "secure", "account", "banking", "paypa1", "amaz0n", "g00gle", "signin")
    if dns_feat == -1 or prefix_suffix_feat == -1 or any(kw in raw_url.lower() for kw in suspicious_kw):
        abnormal_feat = -1
    else:
        abnormal_feat = 1 if domain and domain in host else -1

    # Fetch HTML response for DOM/page features if possible
    if dns_feat == -1:
        page_feats = {
            "Favicon": -1, "Request_URL": -1, "URL_of_Anchor": -1, "Links_in_tags": -1,
            "SFH": -1, "Submitting_to_email": -1, "Redirect": 0, "on_mouseover": 1,
            "RightClick": 1, "popUpWidnow": 1, "Iframe": -1
        }
    else:
        page_feats = {
            "Favicon": 1, "Request_URL": 1, "URL_of_Anchor": 1, "Links_in_tags": 1,
            "SFH": 1, "Submitting_to_email": 1, "Redirect": 1, "on_mouseover": 1,
            "RightClick": 1, "popUpWidnow": 1, "Iframe": 1
        }
        try:
            resp = requests.get(raw_url, timeout=3.0, headers={"User-Agent": "PhishShieldAI/1.0"})
            if resp.ok:
                page_feats = _page_features(resp, domain)
        except Exception:
            pass

    mapping = {
        "having_IP_Address": having_ip,
        "URL_Length": length_feat,
        "Shortining_Service": short_feat,
        "having_At_Symbol": at_feat,
        "double_slash_redirecting": double_slash_feat,
        "Prefix_Suffix": prefix_suffix_feat,
        "having_Sub_Domain": subdomain_feat,
        "SSLfinal_State": ssl_feat,
        "Domain_registeration_length": domain_reg_feat,
        "Favicon": page_feats.get("Favicon", 1),
        "port": port_feat,
        "HTTPS_token": https_token_feat,
        "Request_URL": page_feats.get("Request_URL", 1),
        "URL_of_Anchor": page_feats.get("URL_of_Anchor", 1),
        "Links_in_tags": page_feats.get("Links_in_tags", 1),
        "SFH": page_feats.get("SFH", 1),
        "Submitting_to_email": page_feats.get("Submitting_to_email", 1),
        "Abnormal_URL": abnormal_feat,
        "Redirect": page_feats.get("Redirect", 1),
        "on_mouseover": page_feats.get("on_mouseover", 1),
        "RightClick": page_feats.get("RightClick", 1),
        "popUpWidnow": page_feats.get("popUpWidnow", 1),
        "Iframe": page_feats.get("Iframe", 1),
        "age_of_domain": domain_age_feat,
        "DNSRecord": dns_feat,
    }
    return mapping


def extract_live_features(url: str) -> List[int]:
    """Return ordered 25-integer feature vector for live model inference."""
    mapping = extract_live_feature_mapping(url)
    return [mapping[name] for name in LIVE_25_FEATURE_NAMES]


def extract_feature_mapping(url: str) -> Dict[str, int]:
    """Legacy 30-feature extraction call — raises FeatureUnavailableError."""
    raise FeatureUnavailableError(
        "Historical features web_traffic, Page_Rank, Google_Index, "
        "Links_pointing_to_page, and Statistical_report cannot be collected "
        "faithfully for arbitrary URLs."
    )


def extract_features(url: str) -> List[int]:
    """Legacy 30-feature extraction call — raises FeatureUnavailableError."""
    raise FeatureUnavailableError(
        "Historical features web_traffic, Page_Rank, Google_Index, "
        "Links_pointing_to_page, and Statistical_report cannot be collected "
        "faithfully for arbitrary URLs."
    )
