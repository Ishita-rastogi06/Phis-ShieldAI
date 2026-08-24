"""Standalone provider connectivity health check & canonical scan trace tool.

Run this directly from the project root to verify provider API key validity,
reachability, and canonical scan execution before starting Streamlit:

    python -m diagnostics.provider_health_check

The script:
  1. Sends a real HTTP request to VirusTotal and OpenPhish using test inputs.
  2. Prints the raw HTTP status code and response snippet (with masked keys).
  3. Reports a PASS / WARN / FAIL verdict with a diagnosis note.
  4. Runs two canonical scan traces via analysis.url_analysis_pipeline.analyze_url()
     and prints normalized provider evidence JSON.

Only VirusTotal and OpenPhish are tested because they are the active threat-intel
providers wired into intelligence/provider_manager.py.
"""
from __future__ import annotations

import base64
import json
import os
import sys
import textwrap
import time
from pathlib import Path

# Make sure the project root is on sys.path when run as a module.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import requests
from dotenv import load_dotenv

load_dotenv(dotenv_path=_ROOT / ".env", override=False)

from analysis.url_analysis_pipeline import analyze_url

TEST_URLS = ("https://www.wikipedia.org/", "https://tinyurl.com/")

# ── helpers ─────────────────────────────────────────────────────────────────

def _mask(value: str) -> str:
    if not value:
        return "<MISSING>"
    if len(value) <= 6:
        return f"<{len(value)}-char key>"
    return f"{value[:2]}***{value[-4:]}"


def _print_section(title: str) -> None:
    print()
    print("=" * 64)
    print(f"  {title}")
    print("=" * 64)


def _print_result(label: str, status_code: int | None, body_snippet: str,
                  verdict: str, note: str) -> None:
    code_str = str(status_code) if status_code is not None else "N/A (no response)"
    print(f"  HTTP status : {code_str}")
    print(f"  Body (first 600 chars):")
    for line in textwrap.wrap(body_snippet or "<empty>", width=60, subsequent_indent="    "):
        print(f"    {line}")
    print(f"  Verdict     : {verdict}")
    print(f"  Note        : {note}")


# ── VirusTotal ───────────────────────────────────────────────────────────────

VT_API = "https://www.virustotal.com/api/v3"
VT_TEST_URL = "https://www.google.com"


def _vt_url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def check_virustotal(timeout: float = 10.0) -> dict:
    key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    _print_section(f"VirusTotal  (key: {_mask(key)})")
    print(f"  Test input  : GET URL report for {VT_TEST_URL!r}")
    print(f"  Endpoint    : GET {VT_API}/urls/{{id}}")

    if not key:
        _print_result("virustotal", None, "", "FAIL",
                      "VIRUSTOTAL_API_KEY is missing — adapter will return NOT_CONFIGURED for every scan")
        return {"provider": "virustotal", "verdict": "FAIL", "status_code": None,
                "diagnosis": "a) Key missing/rejected — VIRUSTOTAL_API_KEY not set"}

    uid = _vt_url_id(VT_TEST_URL)
    url = f"{VT_API}/urls/{uid}"
    t0 = time.perf_counter()
    try:
        resp = requests.get(url, headers={"x-apikey": key}, timeout=timeout)
        elapsed = round(time.perf_counter() - t0, 2)
        body = resp.text[:600]
        code = resp.status_code
        print(f"  Elapsed     : {elapsed}s")

        if code == 200:
            verdict, note = "PASS", "Key accepted; existing URL report returned (working correctly)"
        elif code == 404:
            verdict = "PASS"
            note = ("Key accepted (HTTP 404 = no existing report for this URL). "
                    "Provider will return NO_MATCH status — correct behavior.")
        elif code == 401:
            verdict, note = "FAIL", "Key rejected — HTTP 401 Unauthorized; check VIRUSTOTAL_API_KEY value"
        elif code == 403:
            verdict, note = "FAIL", "Key rejected — HTTP 403 Forbidden; check quota/permissions"
        elif code == 429:
            verdict, note = "WARN", "Rate limited — HTTP 429; key is valid but quota exhausted"
        else:
            verdict, note = "WARN", f"Unexpected status {code}; check VT API status page"

        _print_result("virustotal", code, body, verdict, note)
        return {"provider": "virustotal", "verdict": verdict, "status_code": code,
                "diagnosis": note, "elapsed_s": elapsed}

    except requests.Timeout:
        elapsed = round(time.perf_counter() - t0, 2)
        _print_result("virustotal", None, f"Request timed out after {elapsed}s",
                      "WARN", "Network timeout — check firewall/proxy settings")
        return {"provider": "virustotal", "verdict": "WARN", "status_code": None,
                "diagnosis": "Timeout — request never reached provider", "elapsed_s": elapsed}
    except requests.RequestException as exc:
        _print_result("virustotal", None, str(exc), "FAIL",
                      f"Network error: {exc}")
        return {"provider": "virustotal", "verdict": "FAIL", "status_code": None,
                "diagnosis": f"Network/request error: {exc}"}


# ── OpenPhish (no key required) ───────────────────────────────────────────────

OPENPHISH_FEED = "https://openphish.com/feed.txt"


def check_openphish(timeout: float = 10.0) -> dict:
    _print_section("OpenPhish   (no API key required — public feed)")
    print(f"  Test input  : GET range request for {OPENPHISH_FEED}")

    t0 = time.perf_counter()
    try:
        resp = requests.get(OPENPHISH_FEED,
                            headers={"User-Agent": "PhishShieldAI/1.0-diag",
                                     "Range": "bytes=0-199"},
                            timeout=timeout)
        elapsed = round(time.perf_counter() - t0, 2)
        code = resp.status_code
        body = resp.text[:600]
        print(f"  Elapsed     : {elapsed}s")

        if code in (200, 206):
            verdict = "PASS"
            note = "Feed reachable; provider will perform exact-match URL lookups."
        elif code == 429:
            verdict, note = "WARN", "Rate limited by OpenPhish"
        else:
            verdict, note = "WARN", f"Unexpected HTTP {code}"

        _print_result("openphish", code, body, verdict, note)
        return {"provider": "openphish", "verdict": verdict, "status_code": code,
                "diagnosis": note, "elapsed_s": elapsed}

    except requests.Timeout:
        elapsed = round(time.perf_counter() - t0, 2)
        _print_result("openphish", None, f"Timed out after {elapsed}s",
                      "WARN", "Network timeout reaching OpenPhish feed")
        return {"provider": "openphish", "verdict": "WARN", "status_code": None,
                "diagnosis": "Timeout", "elapsed_s": elapsed}
    except requests.RequestException as exc:
        _print_result("openphish", None, str(exc), "FAIL", f"Network error: {exc}")
        return {"provider": "openphish", "verdict": "FAIL", "status_code": None,
                "diagnosis": f"Network error: {exc}"}


# ── Canonical Scans ──────────────────────────────────────────────────────────

def canonical_scans() -> None:
    _print_section("Canonical Scan Traces (analyze_url)")
    for url in TEST_URLS:
        print(f"\n  Scan trace for {url!r}:")
        scan = analyze_url(url, include_enrichment=False)
        output = {
            "normalized_url": scan.get("normalized_url"),
            "provider_statuses": scan.get("provider_statuses"),
            "providers": scan.get("providers"),
        }
        print(textwrap.indent(json.dumps(output, indent=2, default=str), "    "))


# ── main ─────────────────────────────────────────────────────────────────────

def run_all(timeout: float = 10.0) -> list[dict]:
    print()
    print("+--------------------------------------------------------------+")
    print("|     PhishShield AI -- Provider Connectivity Health Check     |")
    print("+--------------------------------------------------------------+")
    print("Keys are read from the project .env file (never printed in full).")

    results = [
        check_virustotal(timeout),
        check_openphish(timeout),
    ]

    print()
    print("=" * 64)
    print("  SUMMARY")
    print("=" * 64)
    all_pass = True
    for r in results:
        icon = "PASS" if r["verdict"] == "PASS" else ("WARN" if r["verdict"] == "WARN" else "FAIL")
        print(f"  [{icon:<4}] {r['provider']:<14} {r['verdict']:<5}  HTTP {r.get('status_code','N/A'):<4}  {r.get('elapsed_s','')}")
        all_pass = all_pass and r["verdict"] == "PASS"

    print()
    if all_pass:
        print("  All providers healthy -- proceeding to canonical scan traces.")
    else:
        print("  One or more providers need attention -- see notes above.")

    canonical_scans()
    return results


if __name__ == "__main__":
    run_all()
