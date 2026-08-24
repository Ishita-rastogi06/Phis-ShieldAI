"""Evidence-based ATT&CK analytical mappings, not threat-actor attribution."""
from __future__ import annotations

from urllib.parse import urlparse

MITRE_TECHNIQUE_URLS = {
    "T1566.002": "https://attack.mitre.org/techniques/T1566/002/",
    "T1036.005": "https://attack.mitre.org/techniques/T1036/005/",
    "T1056.003": "https://attack.mitre.org/techniques/T1056/003/",
    "T1056":     "https://attack.mitre.org/techniques/T1056/",
    "T1583.001": "https://attack.mitre.org/techniques/T1583/001/",
    "T1204.001": "https://attack.mitre.org/techniques/T1204/001/",
}


def map_to_mitre(url: str, similarity: int, risk: int, reasons: list[str], website: dict | None = None) -> list[dict]:
    observed = " ".join(reasons).lower()
    path = urlparse(url if "://" in url else f"https://{url}").path.lower()
    findings: list[dict] = []
    credential_terms = ("login", "signin", "sign-in", "password", "verify", "credential", "account", "secure", "update")

    if risk >= 30 and (any(term in path for term in credential_terms) or "credential" in observed or "verify" in observed):
        findings.append({
            "id": "T1566.002",
            "name": "Phishing: Spearphishing Link",
            "tactic": "Initial Access",
            "reason": "Observed credential-oriented URL path (/verify, /login, /account) or social engineering phishing indicators.",
            "confidence": "observed",
            "url": MITRE_TECHNIQUE_URLS.get("T1566.002", "#")
        })

    if similarity >= 50 or "brand" in observed or "typosquat" in observed:
        findings.append({
            "id": "T1036.005",
            "name": "Masquerading: Match Legitimate Name or Location",
            "tactic": "Defense Evasion",
            "reason": f"Brand detector found {similarity}% domain name / typosquatting similarity with a trusted target brand.",
            "confidence": "observed",
            "url": MITRE_TECHNIQUE_URLS.get("T1036.005", "#")
        })

    forms_val = website.get("forms", 0) if isinstance(website, dict) else 0
    has_forms = (isinstance(forms_val, int) and forms_val > 0) or (isinstance(forms_val, list) and len(forms_val) > 0)
    if (website and has_forms and risk >= 40) or "password" in observed or "credential" in observed:
        findings.append({
            "id": "T1056.003",
            "name": "Input Capture: Web Portal Capture",
            "tactic": "Credential Access",
            "reason": "Phishing website contains interactive form fields or credential harvesting mechanisms.",
            "confidence": "observed",
            "url": MITRE_TECHNIQUE_URLS.get("T1056.003", "#")
        })

    if "less than 30 days" in observed or "newly registered" in observed:
        findings.append({
            "id": "T1583.001",
            "name": "Acquire Infrastructure: Domains",
            "tactic": "Resource Development",
            "reason": "Domain registration is newly created (<30 days old), indicative of disposable phishing infrastructure.",
            "confidence": "analytical",
            "url": MITRE_TECHNIQUE_URLS.get("T1583.001", "#")
        })

    if risk >= 45:
        findings.append({
            "id": "T1204.001",
            "name": "User Execution: Malicious Link",
            "tactic": "Execution",
            "reason": "Observed phishing indicators require target user execution (clicking link or entering data).",
            "confidence": "analytical",
            "url": MITRE_TECHNIQUE_URLS.get("T1204.001", "#")
        })

    return findings
