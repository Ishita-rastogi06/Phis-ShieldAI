"""Passive, bounded website inspection. It never executes page JavaScript."""
from __future__ import annotations

from urllib.parse import urlparse
from functools import lru_cache

import ssl
import requests
from requests.adapters import HTTPAdapter
from bs4 import BeautifulSoup
from security.url_security import UnsafeURLError, normalise_url, validate_redirect

MAX_RESPONSE_BYTES = 1_500_000
TIMEOUT_SECONDS = (1.0, 1.2)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


class _SystemSSLAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context()
        kwargs["ssl_context"] = ctx
        return super().init_poolmanager(*args, **kwargs)


def _get_session() -> requests.Session:
    session = requests.Session()
    session.mount("https://", _SystemSSLAdapter())
    return session


@lru_cache(maxsize=128)
def analyze_website(url: str) -> dict:
    result = {
        "status": "AVAILABLE",
        "ssl": False, "title": None, "reachable": False, "redirects": 0,
        "redirect_chain": [], "status_code": None, "final_url": None, "content_type": None,
        "html": None, "forms": [], "links": [], "scripts": [], "meta": {}, "favicon": None,
        "iframes": 0, "javascript_events": [], "mailto_links": [], "resource_link_ratio": None,
        "popup_indicators": [], "mouseover_indicators": [], "context_menu_indicators": [], "error": None,
    }
    target = normalise_url(url)
    session = _get_session()
    try:
        # Validate every hop: limit to max 3 hops for high-speed performance
        response = None
        chain = []
        for _ in range(3):
            try:
                response = requests.get(target, timeout=TIMEOUT_SECONDS, allow_redirects=False, stream=True, headers=HEADERS)
            except requests.exceptions.SSLError:
                response = session.get(target, timeout=TIMEOUT_SECONDS, allow_redirects=False, stream=True, headers=HEADERS)
            chain.append(response.url)
            if response.is_redirect and response.headers.get("Location"):
                target = validate_redirect(requests.compat.urljoin(response.url, response.headers["Location"]))
                continue
            break
        if response is None:
            raise requests.RequestException("No HTTP response")
        result.update({
            "status_code": response.status_code, "final_url": response.url,
            "redirects": max(0, len(chain) - 1), "redirect_chain": chain,
            "content_type": response.headers.get("Content-Type", ""),
            "ssl": urlparse(response.url).scheme == "https",
        })
        if response.status_code >= 400:
            result["error"] = f"HTTP {response.status_code}"
            return result
        if "html" not in result["content_type"].lower():
            result["error"] = "Response is not HTML; page metadata was not parsed"
            return result
        payload = b"".join(chunk for chunk in response.iter_content(32768) if chunk)[:MAX_RESPONSE_BYTES]
        if len(payload) >= MAX_RESPONSE_BYTES:
            result["error"] = "HTML response exceeded the safe analysis limit"
            return result
        html = payload.decode(response.encoding or "utf-8", errors="replace")
        soup = BeautifulSoup(html, "html.parser")
        result["reachable"] = True
        result["html"] = html
        title = soup.title
        result["title"] = title.get_text(" ", strip=True) if title else None
        result["forms"] = [{"action": form.get("action"), "method": form.get("method", "get").lower()} for form in soup.find_all("form")]
        result["links"] = [anchor.get("href") for anchor in soup.find_all("a", href=True)][:500]
        result["scripts"] = [script.get("src") for script in soup.find_all("script", src=True)][:200]
        result["mailto_links"] = [href for href in result["links"] if isinstance(href, str) and href.lower().startswith("mailto:")]
        resources = len(result["scripts"]) + len(soup.find_all(["img", "link", "video", "audio", "iframe"]))
        result["resource_link_ratio"] = round(resources / max(1, len(result["links"])), 3)
        result["meta"] = {tag.get("name") or tag.get("property"): tag.get("content", "") for tag in soup.find_all("meta") if tag.get("name") or tag.get("property")}
        icon = soup.find("link", rel=lambda value: value and "icon" in value.lower())
        result["favicon"] = icon.get("href") if icon else None
        result["iframes"] = len(soup.find_all(["iframe", "frame"]))
        result["javascript_events"] = sorted({attribute for tag in soup.find_all(True) for attribute in tag.attrs if attribute.lower().startswith("on")})
        html_lower = html.lower()
        result["popup_indicators"] = [token for token in ("window.open", "alert(", "confirm(") if token in html_lower]
        result["mouseover_indicators"] = [token for token in ("onmouseover", "onmouseenter") if token in html_lower]
        result["context_menu_indicators"] = [token for token in ("oncontextmenu", "contextmenu") if token in html_lower]
    except (requests.RequestException, ValueError, UnsafeURLError) as error:
        result["error"] = str(error)
    return result
