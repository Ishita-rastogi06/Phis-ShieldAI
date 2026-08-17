"""Standalone provider connectivity test.

Run this directly from the project root to verify each API key is valid and
each provider is reachable before starting the Streamlit application:

    python -m diagnostics.provider_health_check

For each provider the script:
  1. Sends a real HTTP request to the provider using a known-good test input.
  2. Prints the raw HTTP status code and the first 600 characters of the
     response body (or the exception message on network failure).
  3. Reports a PASS / WARN / FAIL verdict with a diagnosis note.

Test inputs used:
  - VirusTotal : GET existing report for https://www.google.com
  - urlscan.io : search existing scans for wikipedia.org
  - URLhaus     : POST lookup for https://www.google.com  (expect "no_results")

No new submissions are ever made.  The keys are read from the project .env.
"""
from __future__ import annotations

import base64
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
VT_TEST_DOMAIN = "google.com"


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
            verdict, note = "PASS", "Key accepted; existing URL report returned (e → working correctly)"
        elif code == 404:
            verdict = "PASS"
            note = ("Key accepted (HTTP 404 = no existing report for this URL, which is normal "
                    "for a fresh key or a URL that has never been analysed). "
                    "Provider will return NO_MATCH status — this is correct behaviour (e).")
        elif code == 401:
            verdict, note = "FAIL", "a) Key rejected — HTTP 401 Unauthorised; check VIRUSTOTAL_API_KEY value"
        elif code == 403:
            verdict, note = "FAIL", "a) Key rejected — HTTP 403 Forbidden; check quota/permissions"
        elif code == 429:
            verdict, note = "WARN", "c) Rate limited — HTTP 429; key is valid but quota exhausted"
        else:
            verdict, note = "WARN", f"c) Unexpected status {code}; check VT API status page"

        _print_result("virustotal", code, body, verdict, note)
        return {"provider": "virustotal", "verdict": verdict, "status_code": code,
                "diagnosis": note, "elapsed_s": elapsed}

    except requests.Timeout:
        elapsed = round(time.perf_counter() - t0, 2)
        _print_result("virustotal", None, f"Request timed out after {elapsed}s",
                      "WARN", "c) Network timeout — check firewall/proxy settings")
        return {"provider": "virustotal", "verdict": "WARN", "status_code": None,
                "diagnosis": "c) Timeout — request never reached provider", "elapsed_s": elapsed}
    except requests.RequestException as exc:
        _print_result("virustotal", None, str(exc), "FAIL",
                      f"c) Network error: {exc}")
        return {"provider": "virustotal", "verdict": "FAIL", "status_code": None,
                "diagnosis": f"c) Network/request error: {exc}"}


# ── urlscan.io ───────────────────────────────────────────────────────────────

URLSCAN_API = "https://urlscan.io/api/v1/search/"
URLSCAN_TEST_QUERY = 'page.domain:"wikipedia.org"'


def check_urlscan(timeout: float = 10.0) -> dict:
    key = os.getenv("URLSCAN_API_KEY", "").strip()
    _print_section(f"urlscan.io  (key: {_mask(key)})")
    print(f"  Test input  : search for scans matching {URLSCAN_TEST_QUERY!r}")
    print(f"  Endpoint    : GET {URLSCAN_API}")

    if not key:
        _print_result("urlscan", None, "", "FAIL",
                      "URLSCAN_API_KEY is missing — adapter will return NOT_CONFIGURED for every scan")
        return {"provider": "urlscan", "verdict": "FAIL", "status_code": None,
                "diagnosis": "a) Key missing — URLSCAN_API_KEY not set"}

    params = {"q": URLSCAN_TEST_QUERY, "size": 1}
    t0 = time.perf_counter()
    try:
        resp = requests.get(URLSCAN_API, params=params,
                            headers={"API-Key": key, "Accept": "application/json",
                                     "User-Agent": "PhishShieldAI/1.0-diag"},
                            timeout=timeout)
        elapsed = round(time.perf_counter() - t0, 2)
        body = resp.text[:600]
        code = resp.status_code
        print(f"  Elapsed     : {elapsed}s")

        if code == 200:
            total = resp.json().get("total", 0) if resp.headers.get("content-type", "").startswith("application/json") else "?"
            verdict = "PASS"
            note = (f"Key accepted; search returned {total} result(s). "
                    "Provider will return AVAILABLE or NO_MATCH depending on URL (e).")
        elif code in (401, 403):
            verdict, note = "FAIL", "a) Key rejected — HTTP {code}; check URLSCAN_API_KEY value"
        elif code == 429:
            verdict, note = "WARN", "c) Rate limited — HTTP 429; key is valid but quota exhausted"
        else:
            verdict, note = "WARN", f"c) Unexpected status {code}"

        _print_result("urlscan", code, body, verdict, note)
        return {"provider": "urlscan", "verdict": verdict, "status_code": code,
                "diagnosis": note, "elapsed_s": elapsed}

    except requests.Timeout:
        elapsed = round(time.perf_counter() - t0, 2)
        _print_result("urlscan", None, f"Request timed out after {elapsed}s",
                      "WARN", "c) Network timeout")
        return {"provider": "urlscan", "verdict": "WARN", "status_code": None,
                "diagnosis": "c) Timeout", "elapsed_s": elapsed}
    except requests.RequestException as exc:
        _print_result("urlscan", None, str(exc), "FAIL", f"c) Network error: {exc}")
        return {"provider": "urlscan", "verdict": "FAIL", "status_code": None,
                "diagnosis": f"c) Network/request error: {exc}"}


# ── URLhaus ──────────────────────────────────────────────────────────────────

URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/url/"
# google.com is never in URLhaus; the expected response is query_status=no_results.
# This confirms: key valid, request sent, API working, just no malware record.
URLHAUS_TEST_URL = "https://www.google.com"


def check_urlhaus(timeout: float = 10.0) -> dict:
    key = os.getenv("URLHAUS_AUTH_KEY", "").strip()
    _print_section(f"URLhaus     (key: {_mask(key)})")
    print(f"  Test input  : POST URL lookup for {URLHAUS_TEST_URL!r}")
    print(f"  Endpoint    : POST {URLHAUS_API}")
    print(f"  Expected    : HTTP 200 + query_status='no_results'  (google.com not in threat feed)")

    if not key:
        _print_result("urlhaus", None, "", "FAIL",
                      "URLHAUS_AUTH_KEY is missing — adapter will return NOT_CONFIGURED for every scan")
        return {"provider": "urlhaus", "verdict": "FAIL", "status_code": None,
                "diagnosis": "a) Key missing — URLHAUS_AUTH_KEY not set"}

    t0 = time.perf_counter()
    try:
        resp = requests.post(
            URLHAUS_API,
            data={"url": URLHAUS_TEST_URL},
            headers={"Auth-Key": key, "User-Agent": "PhishShieldAI/1.0-diag"},
            timeout=timeout,
        )
        elapsed = round(time.perf_counter() - t0, 2)
        body = resp.text[:600]
        code = resp.status_code
        print(f"  Elapsed     : {elapsed}s")

        if code == 200:
            try:
                data = resp.json()
                qs = data.get("query_status", "")
            except Exception:
                qs = "<non-JSON response>"
            if qs == "no_results":
                verdict = "PASS"
                note = ("Key accepted; query_status='no_results' for google.com is the correct/expected "
                        "response — key is valid, request reached provider (e).")
            elif qs == "ok":
                verdict = "PASS"
                note = "Key accepted; query_status='ok' — provider returned a match record (e)."
            elif qs == "invalid_url":
                verdict = "WARN"
                note = ("query_status='invalid_url' — URLhaus rejected the test URL format. "
                        "Key may be valid but the adapter's POST format may need checking.")
            else:
                verdict = "WARN"
                note = f"query_status={qs!r} — unexpected; key may or may not be valid."
        elif code in (401, 403):
            verdict, note = "FAIL", f"a) Key rejected — HTTP {code}; check URLHAUS_AUTH_KEY value"
        elif code == 429:
            verdict, note = "WARN", "c) Rate limited — HTTP 429; key valid but quota exhausted"
        else:
            verdict, note = "WARN", f"c) Unexpected HTTP {code}"

        _print_result("urlhaus", code, body, verdict, note)
        return {"provider": "urlhaus", "verdict": verdict, "status_code": code,
                "diagnosis": note, "elapsed_s": elapsed}

    except requests.Timeout:
        elapsed = round(time.perf_counter() - t0, 2)
        _print_result("urlhaus", None, f"Request timed out after {elapsed}s",
                      "WARN", "c) Network timeout")
        return {"provider": "urlhaus", "verdict": "WARN", "status_code": None,
                "diagnosis": "c) Timeout", "elapsed_s": elapsed}
    except requests.RequestException as exc:
        _print_result("urlhaus", None, str(exc), "FAIL", f"c) Network error: {exc}")
        return {"provider": "urlhaus", "verdict": "FAIL", "status_code": None,
                "diagnosis": f"c) Network/request error: {exc}"}


# ── OpenPhish (no key required) ───────────────────────────────────────────────

OPENPHISH_FEED = "https://openphish.com/feed.txt"


def check_openphish(timeout: float = 10.0) -> dict:
    _print_section("OpenPhish   (no API key required — public feed)")
    print(f"  Test input  : HEAD/GET {OPENPHISH_FEED}")

    t0 = time.perf_counter()
    try:
        # Use a small range request to avoid downloading the full feed.
        resp = requests.get(OPENPHISH_FEED,
                            headers={"User-Agent": "PhishShieldAI/1.0-diag",
                                     "Range": "bytes=0-199"},
                            timeout=timeout)
        elapsed = round(time.perf_counter() - t0, 2)
        # 206 = partial content (Range accepted); 200 = full response (Range ignored)
        code = resp.status_code
        body = resp.text[:600]
        print(f"  Elapsed     : {elapsed}s")

        if code in (200, 206):
            verdict = "PASS"
            note = "Feed reachable; provider will perform exact-match URL lookups (e)."
        elif code == 429:
            verdict, note = "WARN", "c) Rate limited by OpenPhish"
        else:
            verdict, note = "WARN", f"c) Unexpected HTTP {code}"

        _print_result("openphish", code, body, verdict, note)
        return {"provider": "openphish", "verdict": verdict, "status_code": code,
                "diagnosis": note, "elapsed_s": elapsed}

    except requests.Timeout:
        elapsed = round(time.perf_counter() - t0, 2)
        _print_result("openphish", None, f"Timed out after {elapsed}s",
                      "WARN", "c) Network timeout reaching OpenPhish feed")
        return {"provider": "openphish", "verdict": "WARN", "status_code": None,
                "diagnosis": "c) Timeout", "elapsed_s": elapsed}
    except requests.RequestException as exc:
        _print_result("openphish", None, str(exc), "FAIL", f"c) Network error: {exc}")
        return {"provider": "openphish", "verdict": "FAIL", "status_code": None,
                "diagnosis": f"c) Network error: {exc}"}


# ── main ─────────────────────────────────────────────────────────────────────

def run_all(timeout: float = 10.0) -> list[dict]:
    print()
    print("╔══════════════════════════════════════════════════════════════╗")
    print("║     PhishShield AI — Provider Connectivity Health Check     ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print("Keys are read from the project .env file (never printed in full).")

    results = [
        check_virustotal(timeout),
        check_urlscan(timeout),
        check_urlhaus(timeout),
        check_openphish(timeout),
    ]

    print()
    print("=" * 64)
    print("  SUMMARY")
    print("=" * 64)
    all_pass = True
    for r in results:
        icon = "✓" if r["verdict"] == "PASS" else ("!" if r["verdict"] == "WARN" else "✗")
        print(f"  [{icon}] {r['provider']:<14} {r['verdict']:<5}  HTTP {r.get('status_code','N/A'):<4}  {r.get('elapsed_s','')}")
        all_pass = all_pass and r["verdict"] == "PASS"

    print()
    if all_pass:
        print("  All providers healthy — proceed to Phase 2.")
    else:
        print("  One or more providers need attention — see notes above.")
    print()
    return results


if __name__ == "__main__":
    run_all()
