"""Evidence-grounded deterministic security explanation engine (not generative AI)."""
from __future__ import annotations
from brand_detector import _is_authoritative

def generate_ai_explanation(target, verdict, risk, reasons, brand="Unknown", *, mitre=None, model_available=False):
    observed = list(reasons or [])
    messages = {
        "CONFIRMED_MALICIOUS": ("Confirmed malicious evidence", "Do not visit or interact with this destination."),
        "LIKELY_PHISHING": ("Likely phishing", "Do not enter credentials; independently verify using a known official channel."),
        "SUSPICIOUS": ("Suspicious indicators", "Treat the destination cautiously and verify it independently."),
        "LIKELY_LEGITIMATE": ("Likely legitimate", "Affirmative domain, DNS/TLS, and passive website evidence supported this verdict. Continue normal security caution."),
        "INSUFFICIENT_EVIDENCE": ("Insufficient evidence", "Insufficient live evidence was available for a stronger verdict. Unavailable and no-match sources are not safety evidence."),
    }
    attack_type, strategy = messages.get(verdict, ("Undetermined", "Review available evidence."))
    return {"engine": "deterministic evidence copilot", "attack_type": attack_type,
            "brand": brand.title() if brand != "Unknown" else "No brand impersonation detected",
            "impact": [f"Final evidence-based verdict: {verdict}."], "strategy": strategy,
            "observed_evidence": observed, "mitre": mitre or [], "legacy_model_available": model_available}
