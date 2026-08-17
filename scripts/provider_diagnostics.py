"""Run live, read-only provider probes and two canonical scan traces.

Run from the repository root:
    .venv\\Scripts\\python scripts/provider_diagnostics.py

The script deliberately prints provider response bodies as requested.  It never
prints API keys or request headers.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from analysis.url_analysis_pipeline import analyze_url
from intelligence.diagnostics import load_and_report_provider_configuration

TEST_URLS = ("https://www.wikipedia.org/", "https://tinyurl.com/")


def vt_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def emit_raw(provider: str, target: str, request) -> None:
    try:
        response = request()
        print(f"RAW provider={provider} input={target!r} http_status={response.status_code}")
        print(response.text)
    except requests.RequestException as error:
        print(f"RAW provider={provider} input={target!r} request_error={error!r}")


def direct_probes() -> None:
    keys = {name: os.getenv(name, "").strip() for name in ("VIRUSTOTAL_API_KEY", "URLSCAN_API_KEY", "URLHAUS_AUTH_KEY")}
    for url in TEST_URLS:
        print(f"\n=== Direct read-only probes for {url} ===")
        if keys["VIRUSTOTAL_API_KEY"]:
            emit_raw("virustotal", url, lambda: requests.get(
                f"https://www.virustotal.com/api/v3/urls/{vt_id(url)}",
                headers={"x-apikey": keys["VIRUSTOTAL_API_KEY"]}, timeout=10))
        else: print("RAW provider=virustotal skipped: VIRUSTOTAL_API_KEY missing")
        if keys["URLSCAN_API_KEY"]:
            emit_raw("urlscan", url, lambda: requests.get(
                "https://urlscan.io/api/v1/search/", params={"q": f'task.url.keyword:"{url}"', "size": 3},
                headers={"API-Key": keys["URLSCAN_API_KEY"], "Accept": "application/json", "User-Agent": "PhishShieldAI/diagnostic"}, timeout=10))
        else: print("RAW provider=urlscan skipped: URLSCAN_API_KEY missing")
        if keys["URLHAUS_AUTH_KEY"]:
            emit_raw("urlhaus", url, lambda: requests.post(
                "https://urlhaus-api.abuse.ch/v1/url/", data={"url": url},
                headers={"Auth-Key": keys["URLHAUS_AUTH_KEY"], "User-Agent": "PhishShieldAI/diagnostic"}, timeout=10))
        else: print("RAW provider=urlhaus skipped: URLHAUS_AUTH_KEY missing")


def canonical_scans() -> None:
    for url in TEST_URLS:
        print(f"\n=== Canonical scan trace for {url} ===")
        scan = analyze_url(url, include_enrichment=False)
        print(json.dumps({"normalized_url": scan.get("normalized_url"), "provider_statuses": scan.get("provider_statuses"),
                          "providers": scan.get("providers")}, indent=2, default=str))


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    load_and_report_provider_configuration()
    direct_probes()
    canonical_scans()
