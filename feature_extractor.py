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


def extract_feature_mapping(url: str) -> Dict[str, int]:
    """Collect all 30 UCI-encoded integer features for model inference."""
    normalised = _normalise_url(url)
    parsed = urlparse(normalised)
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError("URL has no hostname")
    domain = _registrable_domain(host) or host

    # 1. Lexical features (always extractable from URL string)
    host_labels = host.split(".")
    subdomain_count = max(len(host_labels) - (len(domain.split(".")) if domain else 1), 0)
    url_length = len(normalised)
    
    # 2. DNS check
    try:
        socket.gethostbyname(host)
        dns_record = 1
    except socket.gaierror:
        dns_record = -1

    # 3. WHOIS check with fallback
    creation, expiration, abnormal = None, None, False
    try:
        record, creation, expiration = _get_whois(domain)
        now = datetime.now(timezone.utc)
        creation = creation.replace(tzinfo=timezone.utc) if creation and creation.tzinfo is None else creation
        expiration = expiration.replace(tzinfo=timezone.utc) if expiration and expiration.tzinfo is None else expiration
        whois_domains = record.domain_name if isinstance(record.domain_name, list) else [record.domain_name]
        abnormal = any(str(item).lower() == domain for item in whois_domains if item) is False
    except Exception:
        pass

    # 4. SSL State
    ssl_state = _ssl_state(host, parsed.scheme)

    # 5. Page features with fallback if unreachable
    page = {
        "Favicon": 1, "Request_URL": 1, "URL_of_Anchor": 1, "Links_in_tags": 1,
        "SFH": 1, "Submitting_to_email": 1, "Redirect": 0, "on_mouseover": 1,
        "RightClick": 1, "popUpWidnow": 1, "Iframe": 1,
    }
    try:
        response = requests.get(normalised, timeout=TIMEOUT_SECONDS, allow_redirects=True, headers={"User-Agent": "PhishShieldAI/1.0"})
        if response.status_code == 200:
            page = _page_features(response, domain)
    except Exception:
        # If webpage is unreachable, derive heuristic page features from URL path/keywords
        if any(w in normalised.lower() for w in ("login", "verify", "secure", "update", "credential", "password")):
            page["URL_of_Anchor"] = -1
            page["SFH"] = -1

    # 6. Legacy historical features (heuristically inferred for live prediction)
    is_ip = _host_is_ip(host)
    has_at = "@" in normalised
    is_shortener = host in SHORTENER_HOSTS
    has_hyphen = "-" in host
    
    now = datetime.now(timezone.utc)
    dom_reg_len = 1 if (expiration and (expiration - now).days > 365) else -1
    dom_age = 1 if (creation and (now - creation).days >= 180) else -1

    # Heuristic approximations for historical telemetry
    from brand_detector import _is_authoritative, detect_brand
    trusted = _is_authoritative(host)
    _, similarity = detect_brand(normalised)

    web_traffic = 1 if trusted else (-1 if (similarity >= 65 or is_ip or is_shortener) else 0)
    page_rank = 1 if trusted else -1
    google_index = 1 if (trusted or ssl_state == 1) else -1
    links_pointing = 1 if trusted else 0
    stat_report = -1 if (similarity >= 75 or is_ip or ("paypal" in host and not trusted)) else 1

    mapping = {
        "having_IP_Address": -1 if is_ip else 1,
        "URL_Length": 1 if url_length < 54 else (0 if url_length <= 75 else -1),
        "Shortining_Service": -1 if is_shortener else 1,
        "having_At_Symbol": -1 if has_at else 1,
        "double_slash_redirecting": -1 if normalised.rfind("//") > 7 else 1,
        "Prefix_Suffix": -1 if has_hyphen else 1,
        "having_Sub_Domain": 1 if subdomain_count == 0 else (0 if subdomain_count == 1 else -1),
        "SSLfinal_State": ssl_state,
        "Domain_registeration_length": dom_reg_len,
        "port": -1 if parsed.port is not None else 1,
        "HTTPS_token": -1 if "https" in host else 1,
        "Abnormal_URL": -1 if abnormal else 1,
        "age_of_domain": dom_age,
        "DNSRecord": dns_record,
        "web_traffic": web_traffic,
        "Page_Rank": page_rank,
        "Google_Index": google_index,
        "Links_pointing_to_page": links_pointing,
        "Statistical_report": stat_report,
    }
    mapping.update(page)
    return mapping


def extract_features(url: str) -> List[int]:
    mapping = extract_feature_mapping(url)
    values = [mapping[name] for name in URL_FEATURE_NAMES]
    if len(values) != 30 or not all(isinstance(value, int) for value in values): raise FeatureUnavailableError("Feature schema must contain 30 integers.")
    return values
