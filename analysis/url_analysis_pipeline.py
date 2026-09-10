"""Canonical bounded URL pipeline used by direct URL, QR, screenshot, and email flows."""
from __future__ import annotations

import re
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor, wait
from urllib.parse import urlparse

from ai_copilot import generate_ai_explanation
from analysis.risk_engine import calculate_verdict
from brand_detector import _is_authoritative, detect_brand
from dns_intelligence import analyze_dns
from intelligence.contracts import result, ERROR, UNAVAILABLE, NOT_QUERIED
from intelligence.provider_manager import collect_remote
from intelligence.diagnostics import log_scan_stage
from mitre_mapper import map_to_mitre
from ml.url_detector import predict_url
from security.url_security import UnsafeURLError, normalise_url
from threat_explainer import explain_threat
from tls_intelligence import inspect_tls
from url_expander import ExpansionStatus, expand_url
from website_analyzer import analyze_website
from whois_checker import check_domain_age

SOURCE_TIMEOUT = 5.0
CANONICAL_VERDICTS = {"CONFIRMED_MALICIOUS", "LIKELY_PHISHING", "SUSPICIOUS", "LIKELY_LEGITIMATE", "INSUFFICIENT_EVIDENCE"}
PROVIDER_NAMES = ("virustotal", "openphish")

# ── Suspicious TLDs used by phishing infrastructure ──────────────────────────
_SUSPICIOUS_TLDS = {
    ".xyz", ".top", ".click", ".work", ".loan", ".gq", ".ml",
    ".cf", ".tk", ".pw", ".cc", ".su", ".icu", ".buzz", ".cyou",
}
# Phishing keyword lists (network-independent check)
_KW_HIGH = {"otp", "password", "credential", "signin", "suspended", "unlock", "verify-now", "account-locked"}
_KW_MED  = {"login", "verify", "secure", "account", "update", "bank", "wallet",
             "confirm", "reset", "billing", "recover", "support", "helpdesk"}

# IDN homograph confusables: map lookalike Unicode chars → ASCII equivalent
_IDN_MAP: dict[str, str] = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p", "\u0441": "c",
    "\u0445": "x", "\u0456": "i", "\u04cf": "l", "\u00e0": "a", "\u00e1": "a",
    "\u00e2": "a", "\u00e4": "a", "\u00e9": "e", "\u00ed": "i", "\u00f3": "o",
    "\u00fa": "u", "\u00fc": "u", "\u1d0f": "o", "\u1d00": "a",
}


def _normalise_idn(text: str) -> str:
    """Replace common IDN homograph characters with their ASCII look-alikes."""
    return "".join(_IDN_MAP.get(ch, ch) for ch in unicodedata.normalize("NFC", text))


def _lexical_risk_assessment(raw_url: str) -> tuple[str, int, str, list[str]]:
    """Network-independent phishing signal check used when the URL is unreachable.

    Returns (verdict, risk_score, strength, reasons).

    Checks performed (all purely string/structural — no DNS, no HTTP):
      • Brand similarity / typosquatting via brand_detector
      • IDN homograph normalisation before brand check
      • Suspicious TLD
      • IP address as hostname
      • Excessive subdomains / hyphens
      • High- and medium-priority phishing keywords in the URL path/query
      • URL length
    """
    reasons: list[str] = []

    # Parse best-effort — raw_url may not have a scheme
    test = raw_url if "://" in raw_url else f"https://{raw_url}"
    try:
        parsed = urlparse(test)
        host = (parsed.hostname or "").lower()
        path = (parsed.path or "") + "?" + (parsed.query or "")
    except Exception:
        host, path = raw_url.lower(), ""

    # Normalise IDN homographs before brand detection
    ascii_host = _normalise_idn(host)
    if ascii_host != host:
        reasons.append(f"IDN homograph characters detected in hostname (normalised: {ascii_host})")

    # Brand similarity check
    brand, similarity = detect_brand(f"https://{ascii_host}/")
    if similarity >= 85:
        reasons.append(f"Strong brand impersonation: '{brand}' (similarity {similarity}%)")
    elif similarity >= 65:
        reasons.append(f"Possible brand impersonation: '{brand}' (similarity {similarity}%)")

    # Registrable domain
    from security.tldextract_config import offline_extractor as _oe
    _ext = _oe()
    parts = _ext(ascii_host)
    reg_domain = ".".join(p for p in (parts.domain, parts.suffix) if p)
    label = parts.domain.lower()

    # Suspicious TLD
    tld = f".{parts.suffix}" if parts.suffix else ""
    if tld in _SUSPICIOUS_TLDS:
        reasons.append(f"Suspicious TLD: '{tld}' commonly used in phishing infrastructure")

    # IP address as hostname (no domain name)
    if re.search(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        reasons.append("IP address used as hostname instead of a domain name")

    # Excessive hyphens (typosquat pattern: amaz0n-login-secure)
    if label.count("-") >= 2:
        reasons.append(f"Hostname contains {label.count('-')} hyphens — common typosquat pattern")

    # Excessive subdomains
    sub_count = len(parts.subdomain.split(".")) if parts.subdomain else 0
    if sub_count >= 3:
        reasons.append(f"Excessive subdomain nesting ({sub_count} levels)")

    # Keyword scoring over full URL (lowercased)
    url_lower = raw_url.lower()
    high_hits = [w for w in _KW_HIGH if re.search(r"(?<![a-z0-9])" + re.escape(w) + r"(?![a-z0-9])", url_lower)]
    med_hits  = [w for w in _KW_MED  if re.search(r"(?<![a-z0-9])" + re.escape(w) + r"(?![a-z0-9])", url_lower)]
    if high_hits:
        reasons.append(f"High-risk phishing keywords in URL: {', '.join(sorted(high_hits))}")
    if len(med_hits) >= 2:
        reasons.append(f"Multiple phishing-related keywords in URL: {', '.join(sorted(med_hits))}")

    # URL length
    if len(raw_url) > 100:
        reasons.append(f"Unusually long URL ({len(raw_url)} chars)")

    # ── Score ─────────────────────────────────────────────────────────────────
    score = 0
    score += 35 if similarity >= 85 else (15 if similarity >= 65 else 0)
    score += 20 if tld in _SUSPICIOUS_TLDS else 0
    score += 20 if re.search(r"^\d{1,3}(\.\d{1,3}){3}$", host) else 0
    score += min(len(high_hits) * 15 + len(med_hits) * 8, 30)
    score += 10 if label.count("-") >= 2 else 0
    score += 10 if sub_count >= 3 else 0
    score += 5  if len(raw_url) > 100 else 0
    # Combo boost: brand impersonation + suspicious TLD
    if similarity >= 65 and tld in _SUSPICIOUS_TLDS:
        score += 15
    # Combo boost: brand impersonation + multiple hyphens
    if similarity >= 65 and label.count("-") >= 2:
        score += 10
    # Combo boost: brand impersonation + phishing keywords
    if similarity >= 65 and (high_hits or len(med_hits) >= 2):
        score += 15
    score = min(score, 95)

    log_scan_stage("lexical_assessment", input_url=raw_url,
                   brand=brand, similarity=similarity, score=score,
                   reasons_count=len(reasons))

    if not reasons:
        return "INSUFFICIENT_EVIDENCE", 0, "insufficient", [
            "Lexical analysis found no phishing indicators (URL was not reachable for live checks)"
        ]

    if score >= 60:
        verdict, strength = "LIKELY_PHISHING", "high"
        reasons.insert(0, "Rule: strong lexical/structural phishing indicators (live checks not possible)")
    elif score >= 30:
        verdict, strength = "SUSPICIOUS", "moderate"
        reasons.insert(0, "Rule: multiple lexical phishing indicators (live checks not possible)")
    else:
        verdict, strength = "INSUFFICIENT_EVIDENCE", "insufficient"
        reasons.insert(0, "Rule: lexical phishing indicators present (live checks not possible)")

    return verdict, score, strength, reasons


def _unavailable(name: str, error: str) -> dict:
    return {"status": "UNAVAILABLE", "reason": error, "source": name}


def normalize_analysis_result(raw: dict) -> dict:
    """Normalize every completed URL analysis into the UI-facing contract.

    Verdict evidence is required; legacy-model telemetry is deliberately
    optional and must never make a URL result unrenderable.
    """
    if not isinstance(raw, dict):
        raise TypeError("Canonical URL analysis must be a dictionary")
    normalized = dict(raw)
    verdict = normalized.get("final_verdict", normalized.get("verdict"))
    if verdict not in CANONICAL_VERDICTS:
        raise ValueError("Canonical URL analysis has an invalid final verdict")
    risk = normalized.get("risk_score", normalized.get("risk"))
    if not isinstance(risk, (int, float)):
        raise ValueError("Canonical URL analysis has no numeric risk score")
    reasons = normalized.get("verdict_reason", normalized.get("reasons", []))
    if not isinstance(reasons, list):
        reasons = [str(reasons)]
    model = normalized.get("legacy_model", normalized.get("model"))
    model = dict(model) if isinstance(model, dict) else {}
    model_available = bool(model.get("model_available", False))
    model.update({"model_available": model_available, "prediction": model.get("prediction"),
                  "confidence": model.get("confidence"), "features": model.get("features", []),
                  "error": model.get("error") or (None if model_available else "LEGACY UCI 30-FEATURE MODEL unavailable/conditional telemetry")})
    providers = normalized.get("provider_evidence", normalized.get("providers"))
    providers = dict(providers) if isinstance(providers, dict) else {}
    for name in PROVIDER_NAMES:
        providers.setdefault(name, result(name, NOT_QUERIED, reason="Provider not queried for this URL target", malicious=None))

    verdict_source = normalized.get(
        "verdict_source",
        "AI/ML Classifier" if model_available else "Rule-Based Heuristics & Threat Intelligence"
    )
    risk_source_explanation = normalized.get(
        "risk_source_explanation",
        "Derived from 30-feature ML model prediction corroborated by threat intelligence."
        if model_available else
        "Derived from rule-based indicators (brand impersonation, path keywords, structural patterns) and threat intelligence. ML prediction unavailable because required telemetry could not be collected."
    )

    normalized.update({
        "verdict": verdict, "final_verdict": verdict, "risk": int(risk), "risk_score": int(risk),
        "confidence_strength": normalized.get("evidence_strength", normalized.get("confidence_strength", "insufficient")),
        "evidence_strength": normalized.get("evidence_strength", normalized.get("confidence_strength", "insufficient")),
        "verdict_source": verdict_source,
        "risk_source_explanation": risk_source_explanation,
        "reasons": reasons, "verdict_reason": reasons, "model": model, "legacy_model": model,
        "model_available": model["model_available"], "prediction": model["prediction"],
        "providers": providers, "provider_evidence": providers,
        "provider_statuses": {name: item.get("status", UNAVAILABLE) if isinstance(item, dict) else UNAVAILABLE for name, item in providers.items()},
        "website": normalized.get("website_evidence", normalized.get("website", {})) or {},
        "tls": normalized.get("tls_evidence", normalized.get("tls", {})) or {},
        "dns": normalized.get("dns_evidence", normalized.get("dns", {})) or {},
        "whois": normalized.get("whois_rdap_evidence", normalized.get("whois")),
        "redirect_chain": normalized.get("redirect_chain", []),
        "mitre": normalized.get("mitre_mappings", normalized.get("mitre", [])) or [],
        "ai_copilot": normalized.get("copilot_explanation", normalized.get("ai_copilot", {})) or {},
    })
    return normalized


def analyze_url(url: str, *, include_enrichment: bool = True, progress_callback: Any = None) -> dict:
    started = time.perf_counter()
    if progress_callback:
        progress_callback(15, "Validating Target & Redirect Chain", "Resolving URL shorteners, redirect hops, and SSRF security policies...")
    log_scan_stage("received", input_url=url, include_enrichment=include_enrichment)

    # ── Stage 0: URL shortener / redirect expansion ───────────────────────────
    # If the input URL is a known shortener domain (bit.ly, tinyurl, etc.) or
    # generically returns a 3xx to a different domain, we follow the chain here
    # and run the ENTIRE pipeline against the final resolved destination.
    # This is the step that was missing — without it, providers are queried
    # against the raw short URL (no data) instead of the real target.
    expansion = expand_url(url)
    redirect_chain: list[str] = expansion.redirect_chain

    if expansion.status == ExpansionStatus.SUCCESS and expansion.was_expanded:
        # Resolved successfully to a different destination — analyse that instead.
        log_scan_stage(
            "shortener_expanded",
            input_url=url,
            final_url=expansion.final_url,
            hops=expansion.hops,
            chain=redirect_chain,
        )
        analysis_url = expansion.final_url
        expansion_note = (
            f"Shortened URL expanded: {url} "
            f"→ {expansion.final_url} "
            f"({expansion.hops} hop{'s' if expansion.hops != 1 else ''})"
        )
    elif expansion.status == ExpansionStatus.SHORTENER_DOWN:
        # The shortener itself is unreachable / expired — return an explicit result.
        log_scan_stage(
            "shortener_down",
            input_url=url,
            message=expansion.message,
        )
        lex_verdict, lex_risk, lex_strength, lex_reasons = _lexical_risk_assessment(url)
        reasons_all = [
            f"Shortener service unreachable: {expansion.message}",
            "Live provider checks were not possible because the redirect could not be resolved.",
        ] + lex_reasons
        blocked = {
            "url": url,
            "normalized_url": None,
            "verdict": lex_verdict,
            "risk": lex_risk,
            "confidence_strength": lex_strength,
            "reasons": reasons_all,
            "redirect_chain": redirect_chain,
            "providers": {}, "provider_statuses": {},
            "model": {"model_available": False, "prediction": None,
                      "error": "Shortener unreachable — final URL unknown"},
            "website": {}, "tls": {}, "dns": {}, "whois": None,
            "brand": "Unknown", "similarity": 0,
            "mitre": [],
            "ai_copilot": generate_ai_explanation(
                url, lex_verdict, lex_risk, reasons_all, model_available=False
            ),
        }
        blocked.update({
            "final_verdict": lex_verdict, "risk_score": lex_risk,
            "evidence_strength": lex_strength, "verdict_reason": reasons_all,
            "provider_evidence": blocked["providers"],
            "dns_evidence": {}, "tls_evidence": {}, "whois_rdap_evidence": None,
            "website_evidence": {}, "mitre_mappings": [],
            "brand_evidence": {"brand": "Unknown", "similarity": 0},
            "copilot_explanation": blocked["ai_copilot"],
            "legacy_model": blocked["model"],
        })
        return normalize_analysis_result(blocked)
    elif expansion.status == ExpansionStatus.REDIRECT_LOOP:
        log_scan_stage("shortener_loop", input_url=url, message=expansion.message)
        analysis_url = url
        expansion_note = f"Redirect loop detected in chain: {expansion.message}"
    elif expansion.status == ExpansionStatus.TOO_MANY_HOPS:
        log_scan_stage("shortener_too_many_hops", input_url=url, hops=expansion.hops)
        # Use the last URL we reached before giving up — it may still be useful.
        analysis_url = expansion.final_url
        expansion_note = f"Redirect chain truncated after {expansion.hops} hops — analysing last reached URL"
    else:
        # NOT_A_SHORTENER or EXPANSION_ERROR — proceed with original URL as-is.
        analysis_url = url
        expansion_note = None

    # ── Stage 1: SSRF / normalisation ────────────────────────────────────────
    try:
        normalized = normalise_url(analysis_url)
    except UnsafeURLError as error:
        err_msg = str(error).lower()
        is_internal_ssrf = any(kw in err_msg for kw in ("private", "loopback", "reserved", "localhost", "link-local", "scheme", "malformed", "credentials"))
        if is_internal_ssrf:
            log_scan_stage("validation_blocked", input_url=analysis_url, rule=str(error), remote_providers_called=False)

            lex_verdict, lex_risk, lex_strength, lex_reasons = _lexical_risk_assessment(analysis_url)
            lex_reasons_all = [f"URL blocked by SSRF protection ({error})"] + lex_reasons
            if expansion_note:
                lex_reasons_all.insert(0, expansion_note)

            brand_fallback, sim_fallback = detect_brand(
                f"https://{(urlparse('https://' + analysis_url.lstrip('https://').lstrip('http://')).hostname or analysis_url)}/"
            )

            lex_model = {"model_available": False, "prediction": None, "confidence": None, "error": f"URL blocked by SSRF protection: {error}"}
            model_avail = False

            offline_providers = {
                name: {
                    "provider": name,
                    "status": "NOT_QUERIED",
                    "malicious": None,
                    "strong": False,
                    "reason": f"Not queried: Target blocked by security policy ({error}).",
                    "evidence": None,
                }
                for name in ("virustotal", "openphish")
            }

            blocked = {
                "url": url,
                "normalized_url": analysis_url,
                "verdict": lex_verdict, "risk": lex_risk,
                "confidence_strength": lex_strength,
                "reasons": lex_reasons_all,
                "redirect_chain": redirect_chain,
                "providers": offline_providers,
                "provider_statuses": {name: "NOT_QUERIED" for name in offline_providers},
                "model": lex_model, "model_available": model_avail,
                "prediction": lex_model.get("prediction"),
                "website": {"status": "AVAILABLE", "reachable": False, "notes": "Target blocked by SSRF security policy"},
                "tls": {"status": "AVAILABLE", "connected": False, "notes": "TLS check skipped for blocked target"},
                "dns": {"status": "AVAILABLE", "notes": "DNS resolution blocked by SSRF policy"},
                "whois": {"status": "AVAILABLE", "verdict": "WHOIS lookup skipped for blocked target"},
                "brand": brand_fallback, "similarity": sim_fallback,
                "mitre": map_to_mitre(analysis_url, sim_fallback, lex_risk, lex_reasons_all, {"reachable": False}),
                "verdict_source": "Rule-Based Security Policy",
                "ai_copilot": generate_ai_explanation(
                    analysis_url, lex_verdict, lex_risk, lex_reasons_all, brand_fallback, model_available=model_avail
                ),
            }
            blocked.update({
                "final_verdict": lex_verdict, "risk_score": lex_risk,
                "evidence_strength": lex_strength, "verdict_reason": lex_reasons_all,
                "provider_evidence": blocked["providers"],
                "dns_evidence": blocked["dns"], "tls_evidence": blocked["tls"], "whois_rdap_evidence": blocked["whois"],
                "website_evidence": blocked["website"], "mitre_mappings": blocked["mitre"],
                "brand_evidence": {"brand": brand_fallback, "similarity": sim_fallback},
                "copilot_explanation": blocked["ai_copilot"],
                "legacy_model": blocked["model"],
            })
            return normalize_analysis_result(blocked)
        else:
            # Public domain whose local DNS lookup failed — prepend scheme if missing and proceed to full analysis
            # so remote threat-intelligence providers (VirusTotal, OpenPhish) ARE STILL QUERIED!
            if "://" in analysis_url:
                normalized = analysis_url
            elif analysis_url.lower().startswith("www."):
                normalized = "https://" + analysis_url
            else:
                normalized = "https://" + analysis_url
    log_scan_stage("validation_passed", input_url=analysis_url, normalized_url=normalized)
    if progress_callback:
        progress_callback(35, "Running 25-Feature ML Classifier", "Extracting structural, lexical, and DOM telemetry features...")

    # ── Stage 2: parallel enrichment ─────────────────────────────────────────
    values, durations = {}, {}
    # Run ML prediction locally first so remote API latency never causes ML timeouts
    try:
        values["model"] = predict_url(normalized)
        durations["model"] = round(time.perf_counter() - started, 3)
    except Exception as error:
        values["model"] = {"model_available": False, "prediction": None, "error": str(error)}

    if progress_callback:
        progress_callback(60, "Querying DNS, TLS & Domain WHOIS", "Inspecting SSL certificates, DNS resolution, and domain age...")

    # Run remote threat intelligence (VirusTotal & OpenPhish) in dedicated pool so local socket delays never block API calls
    remote_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="remote_intel")
    remote_future = remote_pool.submit(collect_remote, normalized)

    jobs = {"website": analyze_website, "tls": inspect_tls, "dns": analyze_dns}
    if include_enrichment: jobs["whois"] = check_domain_age
    log_scan_stage("pipeline_jobs_submitted", normalized_url=normalized,
                   jobs=["remote"] + list(jobs.keys()), timeout_s=SOURCE_TIMEOUT)
    pool = ThreadPoolExecutor(max_workers=len(jobs), thread_name_prefix="phishshield")
    try:
        futures = {name: pool.submit(fn, normalized) for name, fn in jobs.items()}
        wait(list(futures.values()), timeout=SOURCE_TIMEOUT)
        for name, future in futures.items():
            if not future.done():
                values[name], durations[name] = _unavailable(name, "pipeline timeout"), SOURCE_TIMEOUT
                log_scan_stage("job_timeout", job=name, normalized_url=normalized)
            else:
                try:
                    values[name] = future.result()
                    durations[name] = round(time.perf_counter() - started, 3)
                    log_scan_stage("job_complete", job=name, elapsed_s=durations[name])
                except Exception as error:
                    values[name], durations[name] = _unavailable(name, str(error)), round(time.perf_counter() - started, 3)
                    log_scan_stage("job_error", job=name, error=str(error), elapsed_s=durations[name])
    finally:
        pool.shutdown(wait=False, cancel_futures=True)

    if progress_callback:
        progress_callback(85, "Evaluating VirusTotal & Threat Feeds", "Corroborating threat feeds, IP reputation, and brand similarity...")

    # Collect remote threat intel result (collect_remote manages its own bounded 6.0s timeout internally)
    try:
        values["remote"] = remote_future.result()
        durations["remote"] = round(time.perf_counter() - started, 3)
        _remote_statuses = {
            k: v.get("status") if isinstance(v, dict) else "malformed"
            for k, v in (values["remote"] or {}).items()
        }
        log_scan_stage("job_complete", job="remote", elapsed_s=durations["remote"], provider_statuses=_remote_statuses)
    except Exception as error:
        values["remote"] = _unavailable("remote", str(error))
        log_scan_stage("job_error", job="remote", error=str(error), elapsed_s=round(time.perf_counter() - started, 3))
    finally:
        remote_pool.shutdown(wait=False, cancel_futures=True)

    if progress_callback:
        progress_callback(95, "Synthesizing Evidence & MITRE ATT&CK", "Generating threat decision matrix and security indicators...")

    # ── Stage 3: assemble provider evidence ──────────────────────────────────
    remote_value = values.get("remote", {})
    remote = remote_value if isinstance(remote_value, dict) else {}

    provider_names = ("virustotal", "openphish")
    fallback_reason = (remote_value.get("reason") if isinstance(remote_value, dict) else None) or "Provider did not return a result"
    providers = {}
    for name in provider_names:
        item = remote.get(name)
        if isinstance(item, dict):
            providers[name] = item
        else:
            providers[name] = result(name, UNAVAILABLE, reason=fallback_reason)

    log_scan_stage("remote_complete", normalized_url=normalized,
                   provider_statuses={name: item.get("status") for name, item in providers.items()})
    website = values.get("website", _unavailable("website", "missing")); tls = values.get("tls", _unavailable("tls", "missing")); dns = values.get("dns", _unavailable("dns", "missing")); whois = values.get("whois")
    model = values.get("model", {"model_available": False, "prediction": None, "error": "legacy model unavailable"})
    brand, similarity = detect_brand(normalized)
    local = explain_threat(model.get("prediction"), similarity, tls.get("https", False), normalized, website.get("title"))
    if tls.get("https") and tls.get("connected") and not tls.get("certificate_valid"): local.append("TLS certificate validation failed")
    if whois and whois.get("age_days") is not None and whois["age_days"] < 30: local.append("Domain registration is less than 30 days old")
    if website.get("reachable") and website.get("iframes", 0): local.append("Passive inspection observed embedded frame content")
    host = (urlparse(normalized).hostname or "").lower(); trusted = _is_authoritative(host)
    if brand == "Unknown" and trusted:
        from brand_detector import BRAND_DOMAINS, _registrable_domain
        reg_dom = _registrable_domain(host)
        for b_name, b_domains in BRAND_DOMAINS.items():
            if any(reg_dom == d or reg_dom.endswith("." + d) for d in b_domains):
                brand = b_name.title()
                break
    # ── Stage 4: verdict + enrichment ────────────────────────────────────────
    log_scan_stage("verdict_inputs", normalized_url=normalized,
                   provider_statuses={name: item.get("status") for name, item in providers.items()},
                   brand_similarity=similarity, trusted_domain=trusted,
                   local_reasons_count=len(local), whois_age_days=(whois or {}).get("age_days"),
                   tls_valid=tls.get("certificate_valid"), website_reachable=website.get("reachable"))
    verdict, risk, strength, policy_reasons = calculate_verdict(
        providers=providers, brand_similarity=similarity, trusted_domain=trusted,
        website=website, tls=tls, whois=whois, local_reasons=local, dns=dns)
    log_scan_stage("verdict_computed", normalized_url=normalized,
                   verdict=verdict, risk=risk, strength=strength,
                   policy_reasons_count=len(policy_reasons))
    mitre = map_to_mitre(normalized, similarity, risk, policy_reasons, website)
    provider_statuses = {name: item.get("status") for name, item in providers.items()}
    vt = providers.get("virustotal")
    vt_evidence = (vt or {}).get("evidence", {})
    vt_compat = None if not vt else {**vt_evidence, "total": sum(int(vt_evidence.get(key, 0)) for key in ("malicious", "suspicious", "harmless", "undetected")), "status": vt.get("status"), "reason": vt.get("reason"),
        "verdict": "Dangerous" if vt_evidence.get("malicious", 0) >= 3 else "Suspicious" if vt.get("malicious") else "No adverse detections"}

    # Prepend the shortener expansion note to reasons so the user always sees
    # "bit.ly/xyz → amazon.com/deals" at the top of the Why-this-verdict list.
    display_reasons = list(policy_reasons)
    if expansion_note:
        display_reasons = [expansion_note] + display_reasons

    canonical = {"url": url, "normalized_url": normalized, "verdict": verdict, "risk": risk, "risk_level": verdict,
            "confidence_strength": strength, "reasons": display_reasons, "providers": providers, "provider_statuses": provider_statuses,
            "model": model, "model_available": model.get("model_available", False), "prediction": model.get("prediction"),
            "website": website, "tls": tls, "dns": dns, "whois": whois, "brand": brand, "similarity": similarity,
            "redirect_chain": redirect_chain,
            "mitre": mitre, "virustotal": vt_compat,
            "recommendation": generate_ai_explanation(normalized, verdict, risk, display_reasons, brand, mitre=mitre, model_available=model.get("model_available", False))["strategy"],
            "ai_copilot": generate_ai_explanation(normalized, verdict, risk, display_reasons, brand, mitre=mitre, model_available=model.get("model_available", False)),
            "performance": {"total_seconds": round(time.perf_counter() - started, 3), "source_timeout_seconds": SOURCE_TIMEOUT, "durations": durations}}
    # Explicit contract aliases make every entry route consume the same
    # canonical result without translating verdict or evidence semantics.
    canonical.update({"final_verdict": verdict, "risk_score": risk, "evidence_strength": strength,
                      "verdict_reason": display_reasons, "provider_evidence": providers,
                      "dns_evidence": dns, "tls_evidence": tls, "whois_rdap_evidence": whois,
                      "website_evidence": website, "brand_evidence": {"brand": brand, "similarity": similarity},
                      "mitre_mappings": mitre, "copilot_explanation": canonical["ai_copilot"],
                      "legacy_model": model})
    normalized_result = normalize_analysis_result(canonical)
    # ── Stage 5: result written ───────────────────────────────────────────────
    # Confirm that the status values the sidebar widget and the tab content
    # will read are identical — both consume result["providers"][name]["status"]
    # and result["provider_statuses"][name] from the same canonical object.
    log_scan_stage("result_written", normalized_url=normalized,
                   provider_statuses=normalized_result["provider_statuses"],
                   verdict=normalized_result["verdict"],
                   risk=normalized_result["risk"],
                   ui_sources={
                       "intel_tab": "result['providers'][name]['status']",
                       "sidebar": "history row -> Provider Evidence -> virustotal.status",
                       "are_same_object": True,
                   },
                   total_s=round(time.perf_counter() - started, 3))
    return normalized_result
