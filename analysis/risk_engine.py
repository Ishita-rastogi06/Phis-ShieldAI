"""Evidence policy for the canonical platform verdict; missing data is never safety evidence."""
from __future__ import annotations

VERDICTS = ("CONFIRMED_MALICIOUS", "LIKELY_PHISHING", "SUSPICIOUS", "LIKELY_LEGITIMATE", "INSUFFICIENT_EVIDENCE")


def calculate_verdict(*, providers: dict, brand_similarity: int, trusted_domain: bool, website: dict,
                      tls: dict, whois: dict | None, local_reasons: list[str], dns: dict | None = None) -> tuple[str, int, str, list[str]]:
    reasons: list[str] = []
    malicious = [item for item in providers.values() if item.get("malicious")]
    strong = [item for item in malicious if item.get("strong")]
    vt = providers.get("virustotal", {}).get("evidence", {})
    if providers.get("urlhaus", {}).get("strong"):
        reasons.append("Rule: active URLhaus malware-distribution record")
    if providers.get("openphish", {}).get("strong"):
        reasons.append("Rule: exact OpenPhish phishing-feed match")
    if vt.get("malicious", 0) >= 3:
        reasons.append("Rule: strong VirusTotal malicious-detection consensus")
    # An active URLhaus record and a strong VT consensus are independently
    # sufficient.  A phishing-feed hit is valuable, but is deliberately not
    # promoted to "confirmed" unless another independent source corroborates it.
    if providers.get("urlhaus", {}).get("strong") or vt.get("malicious", 0) >= 3 or len(malicious) >= 2:
        return "CONFIRMED_MALICIOUS", min(100, 85 + 5 * len(strong)), "strong", reasons
    credential_page = bool(website.get("forms")) and any("credential" in x.lower() or "login" in x.lower() or "password" in x.lower() for x in local_reasons)
    if brand_similarity >= 85 and credential_page:
        reasons.append("Rule: strong brand impersonation corroborated by credential-oriented local evidence")
        return "LIKELY_PHISHING", 75, "high", reasons + local_reasons
    if providers.get("openphish", {}).get("malicious") and local_reasons:
        reasons.append("Rule: OpenPhish feed match corroborated by local phishing indicators")
        return "LIKELY_PHISHING", 70, "high", reasons + local_reasons
    suspicious_count = len(local_reasons) + (1 if brand_similarity >= 65 else 0) + (1 if malicious else 0)
    if suspicious_count >= 2:
        reasons.append("Rule: multiple local or reputation indicators require review")
        return "SUSPICIOUS", min(65, 30 + suspicious_count * 10), "moderate", reasons + local_reasons
    # A legitimate conclusion requires affirmative observations, not merely a
    # reputation-provider no-match. DNS is intentionally supportive rather
    # than mandatory: an authoritative site can be reachable through HTTPS
    # even when one DNS record type is unavailable.
    dns_observed = bool((dns or {}).get("a_records") or (dns or {}).get("aaaa_records"))
    # Two tiers of positive inspection:
    #   Tier 1 (authoritative + reachable): hardcoded trusted domain with
    #           successful HTTP fetch. Strongest signal.
    #   Tier 1b (authoritative + TLS valid, page may 404): A trusted domain
    #           whose specific page returned 4xx (e.g. a private Gist, a
    #           deep-link that moved) is still domain-trustworthy — the page
    #           not existing ≠ the domain being malicious.  Requires TLS valid
    #           and VT clean (or no VT data at all, i.e. NO_MATCH).
    #   Tier 2 (reputation-corroborated): VT AVAILABLE + malicious=0 + TLS
    #           valid + website reachable — sufficient for non-hardcoded but
    #           clearly legitimate domains such as mozilla.org, python.org.
    vt_item = providers.get("virustotal", {})
    vt_status = vt_item.get("status", "")
    vt_available_clean = (
        vt_status == "AVAILABLE"
        and int((vt_item.get("evidence") or {}).get("malicious", 0) or 0) == 0
        and int((vt_item.get("evidence") or {}).get("suspicious", 0) or 0) == 0
    )
    vt_no_adverse = vt_available_clean or vt_status in ("NO_MATCH", "NOT_CONFIGURED", "TIMEOUT", "")

    # Tier 1b: trusted domain + valid TLS + no adverse VT data (page may 404).
    trusted_tls_only = (
        trusted_domain
        and tls.get("certificate_valid")
        and vt_no_adverse
    )
    # Tier 1 / Tier 2: needs website reachable too.
    positive_inspection = tls.get("certificate_valid") and (
        (trusted_domain and website.get("reachable"))          # Tier 1
        or (vt_available_clean and website.get("reachable"))   # Tier 2
        or trusted_tls_only                                    # Tier 1b (4xx page on trusted domain)
    )
    # A single VT engine flag is preserved as evidence but is not sufficient
    # to negate independently observed authoritative DNS/TLS/HTTP evidence.
    # Strong consensus is handled above; two-engine consensus remains
    # suspicious below. Other provider hits keep their own adverse semantics.
    vt_malicious = int(vt.get("malicious", 0) or 0)
    adverse = brand_similarity >= 65 or vt_malicious >= 2 or any(
        item.get("malicious") for name, item in providers.items() if name != "virustotal"
    )
    if positive_inspection and not adverse:
        if trusted_domain and not website.get("reachable"):
            tier = "authoritative domain (TLS valid; specific page unavailable but domain trusted)"
        elif trusted_domain:
            tier = "authoritative domain"
        else:
            tier = "VT-clean reputation-corroborated domain"
        reasons.append(
            f"Rule: {tier} with successful TLS and benign passive inspection"
            + (" and DNS evidence" if dns_observed else "")
        )
        return "LIKELY_LEGITIMATE", 10, "moderate", reasons
    available = [item for item in providers.values() if item.get("status") in {"AVAILABLE", "NO_MATCH"}]
    if local_reasons:
        return "SUSPICIOUS", 30, "low", ["Rule: local suspicious indicators without reputation confirmation"] + local_reasons
    if not available:
        reasons.append("Rule: no reputation provider produced usable evidence")
    else:
        reasons.append("Rule: no affirmative safety evidence; reputation no-match is not a clean verdict")
    return "INSUFFICIENT_EVIDENCE", 0, "insufficient", reasons


# Compatibility for older callers; platform code uses calculate_verdict.
def calculate_risk(**kwargs):
    verdict, risk, _strength, reasons = calculate_verdict(providers={}, brand_similarity=kwargs.get("brand_similarity", 0),
        trusted_domain=kwargs.get("trusted_domain", False), website=kwargs.get("website", {}), tls=kwargs.get("tls", {}),
        whois=kwargs.get("whois"), local_reasons=[], dns=kwargs.get("dns"))
    return risk, verdict, reasons
