"""Evidence-based ATT&CK analytical mappings, not threat-actor attribution."""
from __future__ import annotations

from urllib.parse import urlparse


def map_to_mitre(url: str, similarity: int, risk: int, reasons: list[str], website: dict | None = None) -> list[dict]:
    observed = " ".join(reasons).lower()
    path = urlparse(url if "://" in url else f"https://{url}").path.lower()
    findings: list[dict] = []
    credential_terms = ("login", "signin", "sign-in", "password", "verify", "credential", "account")
    # A generic login path is not ATT&CK evidence by itself.  Require the
    # pipeline to have observed adverse evidence before adding a mapping.
    if risk >= 30 and (any(term in path for term in credential_terms) or "credential" in observed):
        findings.append({"id": "T1566.002", "name": "Phishing: Spearphishing Link", "tactic": "Initial Access", "reason": "Credential-oriented URL path or observed credential-collection indicator.", "confidence": "observed"})
    if similarity >= 65:
        findings.append({"id": "T1036.005", "name": "Masquerading: Match Legitimate Name or Location", "tactic": "Defense Evasion", "reason": "Brand detector found meaningful hostname similarity.", "confidence": "observed"})
    # Embedded frames are commonplace on legitimate sites. Map Input Capture
    # only when the canonical evidence is already materially adverse.
    if website and website.get("iframes", 0) > 0 and risk >= 40:
        findings.append({"id": "T1056", "name": "Input Capture", "tactic": "Credential Access", "reason": "Observed embedded frame content together with adverse phishing evidence.", "confidence": "analytical"})
    if risk >= 50 and ("malicious" in observed or "brand" in observed):
        findings.append({"id": "T1204.001", "name": "User Execution: Malicious Link", "tactic": "Execution", "reason": "Multiple observed phishing indicators require a user to follow the supplied link.", "confidence": "analytical"})
    return findings
