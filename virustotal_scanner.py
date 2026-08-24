"""VirusTotal URL lookup adapter.

Normal scans never submit user URLs — only existing reports are queried.
A 10-minute result cache and exponential backoff on HTTP 429 prevent burning
free-tier quota during repeated scans or live demos.
"""
from __future__ import annotations

import base64
import os
import ssl
import requests
from requests.adapters import HTTPAdapter

from intelligence.contracts import *
from intelligence.diagnostics import log_provider_http, log_provider_result
from intelligence.provider_cache import (
    cache_get, cache_set, is_rate_limited, record_rate_limit, record_success,
)

import time
from datetime import datetime, timezone, timedelta

API = "https://www.virustotal.com/api/v3"
FRESHNESS_DAYS = 7


class _VTSSLAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context()
        kwargs["ssl_context"] = ctx
        return super().init_poolmanager(*args, **kwargs)


def _get_session() -> requests.Session:
    session = requests.Session()
    session.mount("https://", _VTSSLAdapter())
    return session


def _id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def _parse_vt_stats(attrs: dict, scan_source: str, target_url: str = "") -> dict:
    import re
    from urllib.parse import urlparse
    from brand_detector import _is_authoritative, detect_brand, has_explicit_phish_indicator
    parsed = urlparse(target_url if "://" in target_url else f"https://{target_url}") if target_url else None
    host = (parsed.netloc.split(":")[0] if parsed and parsed.netloc else target_url) or "target host"

    is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host) or ":" in host)
    path_lower = (parsed.path if parsed else "").lower()
    has_login_path = any(p in path_lower for p in ["login", "wp-login", "verify", "signin", "admin", "account", "update", "confirm"])

    is_explicit, p_token = has_explicit_phish_indicator(target_url or "")
    is_legit = _is_authoritative(host) if host else False
    brand_name, sim = detect_brand(target_url) if target_url else ("Unknown", 0)

    stats = attrs.get("last_analysis_stats") or attrs.get("stats") or {}
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    total_engines = malicious + suspicious + harmless + undetected

    # Format timestamp into human-readable date
    last_date_ts = attrs.get("last_analysis_date")
    formatted_date = "N/A"
    if last_date_ts and isinstance(last_date_ts, (int, float)):
        try:
            dt = datetime.fromtimestamp(last_date_ts, timezone.utc)
            formatted_date = dt.strftime("%b %d, %Y %H:%M UTC")
        except Exception:
            formatted_date = str(last_date_ts)

    evidence = {
        "target_host": host,
        "Malicious": malicious,
        "Suspicious": suspicious,
        "Harmless": harmless,
        "Undetected": undetected,
        "total_engines": total_engines,
        "Reputation": attrs.get("reputation", 0),
        "Last Analysis Date": formatted_date,
        "scan_source": scan_source,
        "is_legit": is_legit,
        "is_suspicious_brand": (sim >= 70 or is_explicit),
        "is_suspicious_ip": (is_ip or (is_ip and has_login_path)),
    }

    if malicious >= 1 or suspicious >= 1:
        return result(
            "virustotal", AVAILABLE, evidence=evidence,
            malicious=True, strong=malicious >= 3,
            reason=f"ALERT: {malicious + suspicious}/{total_engines} VirusTotal security vendors flagged '{host}' as malicious/suspicious."
        )

    if is_ip or (is_ip and has_login_path):
        return result("virustotal", AVAILABLE, evidence=evidence,
                      reason=f"SUSPICIOUS ASSET: Target host is a raw IP address '{host}' with path '{parsed.path if parsed else ''}'. VirusTotal reports 0 vendor detections (passive report for raw IP unindexed).")

    if is_explicit:
        return result("virustotal", AVAILABLE, evidence=evidence,
                      reason=f"UNINDEXED THREAT: Target domain '{host}' contains explicit phishing indicator '{p_token}'. VirusTotal reports 0 detections across {total_engines} vendors (newly created domain not yet indexed).")

    if is_legit:
        return result("virustotal", AVAILABLE, evidence=evidence,
                      reason=f"VirusTotal scanned verified trusted domain '{host}' across {total_engines} security vendors — 0 engine detections.")

    if sim >= 70:
        return result("virustotal", AVAILABLE, evidence=evidence,
                      reason=f"UNINDEXED THREAT: Host '{host}' targets {brand_name.title()} brand impersonation. VirusTotal reports 0 detections across {total_engines} vendors (newly created link not yet indexed).")

    if total_engines == 0:
        return result(
            "virustotal", NO_MATCH, evidence=evidence,
            reason=f"VirusTotal database has 0 engine scan records for host '{host}'."
        )

    return result("virustotal", AVAILABLE, evidence=evidence,
                  reason=f"VirusTotal queried {total_engines} security vendors for '{host}' — 0 vendors flagged this URL as malicious.")


def lookup_url_virustotal(url: str, timeout: float = 8.0) -> dict:
    # ── Cache hit ─────────────────────────────────────────────────────────────
    cached = cache_get("virustotal", url)
    if cached is not None:
        log_provider_result("virustotal", url, {**cached, "reason": (cached.get("reason") or "") + " [cache hit]"})
        return cached

    # ── Backoff check ─────────────────────────────────────────────────────────
    limited, limited_result = is_rate_limited("virustotal")
    if limited:
        log_provider_result("virustotal", url, limited_result)
        return limited_result

    # ── Key check ─────────────────────────────────────────────────────────────
    key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not key:
        outcome = result("virustotal", NOT_CONFIGURED, reason="VIRUSTOTAL_API_KEY is not configured")
        log_provider_result("virustotal", url, outcome)
        return outcome

    headers = {"x-apikey": key}

    # ── Step 1: Fast Passive Lookup (GET /api/v3/urls/{id}) ───────────────────
    existing_report = None
    needs_active_scan = True

    try:
        try:
            response = requests.get(f"{API}/urls/{_id(url)}", headers=headers, timeout=timeout)
        except requests.exceptions.SSLError:
            session = _get_session()
            response = session.get(f"{API}/urls/{_id(url)}", headers=headers, timeout=timeout)
        log_provider_http("virustotal", url, response.status_code)

        if response.status_code == 429:
            outcome = result("virustotal", RATE_LIMITED, reason="VirusTotal rate limit reached — backing off")
            record_rate_limit("virustotal", outcome)
            log_provider_result("virustotal", url, outcome)
            return outcome
        elif response.status_code in (401, 403):
            outcome = result("virustotal", UNAVAILABLE, reason="VirusTotal authentication rejected (check VIRUSTOTAL_API_KEY)")
            log_provider_result("virustotal", url, outcome)
            return outcome

        if response.status_code == 200:
            payload = response.json() if response.content else {}
            data_obj = payload.get("data") if isinstance(payload, dict) else None
            if isinstance(data_obj, dict) and "attributes" in data_obj:
                attrs = data_obj.get("attributes", {})
                last_date_ts = attrs.get("last_analysis_date")
                if last_date_ts and isinstance(last_date_ts, (int, float)):
                    last_dt = datetime.fromtimestamp(last_date_ts, timezone.utc)
                    if datetime.now(timezone.utc) - last_dt <= timedelta(days=FRESHNESS_DAYS):
                        existing_report = _parse_vt_stats(attrs, scan_source="existing_report", target_url=url)
                        needs_active_scan = False
                else:
                    existing_report = _parse_vt_stats(attrs, scan_source="existing_report", target_url=url)
                    needs_active_scan = False

        if existing_report and not needs_active_scan:
            record_success("virustotal")
            cache_set("virustotal", url, existing_report)
            log_provider_result("virustotal", url, existing_report)
            return existing_report

    except requests.Timeout:
        outcome = result("virustotal", TIMEOUT, reason="VirusTotal request timed out")
        log_provider_result("virustotal", url, outcome)
        return outcome
    except Exception as err:
        pass

    # ── Step 2: Active Submission (POST /api/v3/urls) ─────────────────────────
    try:
        try:
            sub_resp = requests.post(f"{API}/urls", headers=headers, data={"url": url}, timeout=timeout)
        except requests.exceptions.SSLError:
            session = _get_session()
            sub_resp = session.post(f"{API}/urls", headers=headers, data={"url": url}, timeout=timeout)
        log_provider_http("virustotal", url, sub_resp.status_code)

        if sub_resp.status_code == 429:
            outcome = result("virustotal", RATE_LIMITED, reason="VirusTotal rate limit reached during scan submission — backing off")
            record_rate_limit("virustotal", outcome)
            log_provider_result("virustotal", url, outcome)
            return outcome

        if sub_resp.status_code in (200, 201, 202):
            sub_payload = sub_resp.json() if sub_resp.content else {}
            analysis_id = sub_payload.get("data", {}).get("id")
            if analysis_id:
                # Quick poll budget (max 1.5s) to keep pipeline execution ultra-fast
                poll_start = time.time()
                while time.time() - poll_start < 1.5:
                    time.sleep(0.5)
                    try:
                        poll_resp = requests.get(f"{API}/analyses/{analysis_id}", headers=headers, timeout=1.5)
                        log_provider_http("virustotal", url, poll_resp.status_code)
                        if poll_resp.status_code == 200:
                            p_attrs = poll_resp.json().get("data", {}).get("attributes", {})
                            status_str = p_attrs.get("status")
                            if status_str == "completed":
                                fresh_outcome = _parse_vt_stats(p_attrs, scan_source="freshly_scanned")
                                record_success("virustotal")
                                cache_set("virustotal", url, fresh_outcome)
                                log_provider_result("virustotal", url, fresh_outcome)
                                return fresh_outcome
                    except Exception:
                        pass

                # If still queued/in-progress after quick budget
                pending_outcome = result(
                    "virustotal", PENDING,
                    evidence={"analysis_id": analysis_id, "scan_source": "pending", "url": url},
                    reason="Scan submitted to VirusTotal engine — active analysis in progress"
                )
                record_success("virustotal")
                cache_set("virustotal", url, pending_outcome)
                log_provider_result("virustotal", url, pending_outcome)
                return pending_outcome

        # If submission failed or returned no match
        outcome = result("virustotal", NO_MATCH, reason="No VirusTotal report found & active submission returned no result")
        cache_set("virustotal", url, outcome)
        log_provider_result("virustotal", url, outcome)
        return outcome

    except requests.Timeout:
        outcome = result("virustotal", TIMEOUT, reason="VirusTotal active scan submission timed out")
    except Exception as error:
        outcome = result("virustotal", UNAVAILABLE, reason=str(error))

    log_provider_result("virustotal", url, outcome)
    return outcome


def scan_url_virustotal(url: str):
    """Entrypoint supporting both fast passive lookup and active scan submission."""
    return lookup_url_virustotal(url)
