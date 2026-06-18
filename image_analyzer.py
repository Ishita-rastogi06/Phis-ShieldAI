import easyocr
import re

reader = easyocr.Reader(['en'])

# ── HIGH-SIGNAL keywords ─────────────────────────────────────────────────────
# These are genuinely suspicious even in isolation on a screenshot
HIGH_RISK_KEYWORDS = [
    "otp", "cvv", "pin", "password", "enter your password",
    "card number", "debit card", "credit card",
    "kyc", "aadhar", "aadhaar", "pan card",
    "tax refund", "income tax notice",
    "winner", "prize", "you have won", "congratulations you",
    "free gift", "you have been selected",
    "scan below", "scan qr",
    "act now", "expires soon", "last chance", "final notice",
    "suspended", "locked", "deactivated", "blocked",
]

# ── MEDIUM-SIGNAL keywords ────────────────────────────────────────────────────
# Common on BOTH legitimate and phishing pages — only flag when several appear
MEDIUM_RISK_KEYWORDS = [
    "login", "sign in", "log in", "signin",
    "verify", "verification", "confirm",
    "account", "username",
    "update", "reactivate", "restricted", "limited",
    "urgent", "immediately", "action required",
    "billing", "payment", "transaction", "refund", "wallet",
    "bank", "24 hours", "48 hours",
    "click here", "tap here", "click the link",
    "official notice", "gov",
]

HIGH_RISK_WEIGHTS = {
    "cvv": 30, "card number": 28, "debit card": 22, "credit card": 22,
    "otp": 25, "pin": 20, "password": 20, "enter your password": 22,
    "kyc": 20, "aadhar": 18, "aadhaar": 18, "pan card": 18,
    "tax refund": 20, "income tax notice": 18,
    "winner": 18, "prize": 18, "you have won": 20, "congratulations you": 15,
    "free gift": 15, "you have been selected": 18,
    "scan below": 12, "scan qr": 12,
    "act now": 14, "expires soon": 14, "last chance": 14, "final notice": 16,
    "suspended": 15, "locked": 12, "deactivated": 14, "blocked": 10,
}

MEDIUM_RISK_WEIGHTS = {
    "login": 5, "sign in": 5, "log in": 5, "signin": 5,
    "verify": 5, "verification": 5, "confirm": 5,
    "account": 3, "username": 4,
    "update": 3, "reactivate": 7, "restricted": 7, "limited": 5,
    "urgent": 8, "immediately": 7, "action required": 10,
    "billing": 5, "payment": 5, "transaction": 4, "refund": 6, "wallet": 6,
    "bank": 5, "24 hours": 8, "48 hours": 8,
    "click here": 8, "tap here": 7, "click the link": 10,
    "official notice": 8, "gov": 4,
}


def _find_urls(text):
    return re.findall(r'https?://\S+|www\.\S+', text, re.IGNORECASE)


def analyze_screenshot(image_path):
    results = reader.readtext(image_path, detail=0)
    extracted_text = " ".join(results)
    text_lower = extracted_text.lower()

    # Collect keyword hits
    found_high = []
    for word in HIGH_RISK_KEYWORDS:
        if word.lower() in text_lower:
            found_high.append(word)

    found_medium = []
    for word in MEDIUM_RISK_KEYWORDS:
        if word.lower() in text_lower and word.lower() not in [h.lower() for h in found_high]:
            found_medium.append(word)

    # ── Risk calculation ────────────────────────────────────────────────────
    risk = 0

    # High-risk keywords contribute their full weight
    for kw in found_high:
        risk += HIGH_RISK_WEIGHTS.get(kw.lower(), 10)

    # Medium-risk keywords only contribute meaningfully when 3+ co-occur
    # First 2 are noise (legitimate pages hit them all the time)
    if len(found_medium) >= 3:
        for kw in found_medium[2:]:   # skip first 2 as baseline noise
            risk += MEDIUM_RISK_WEIGHTS.get(kw.lower(), 3)
    elif len(found_medium) == 2 and len(found_high) >= 1:
        # Medium pair + at least one high-risk word = worth scoring
        for kw in found_medium:
            risk += MEDIUM_RISK_WEIGHTS.get(kw.lower(), 3) // 2

    # Combination bonus: high + medium together amplify risk
    if len(found_high) >= 2 and len(found_medium) >= 2:
        risk += 10
    if len(found_high) >= 3:
        risk += 10

    # URLs in screenshot
    found_urls = _find_urls(extracted_text)
    if found_urls:
        risk += 8

    risk = min(risk, 95)

    # ── Build indicators (only meaningful ones) ─────────────────────────────
    indicators = []

    if found_high:
        indicators.append(
            f"High-risk indicators found: {', '.join(set(found_high))}"
        )

    # Only report medium keywords if there are enough to be meaningful
    if len(found_medium) >= 3:
        indicators.append(
            f"Multiple suspicious patterns detected: {', '.join(found_medium[:6])}"
        )

    if any(w in text_lower for w in ["password", "cvv", "pin", "card number"]):
        indicators.append("Credential or card data collection attempt suspected.")

    if "otp" in text_lower:
        indicators.append("OTP theft pattern detected.")

    if any(w in text_lower for w in ["suspended", "locked", "deactivated", "blocked"]):
        indicators.append("Account lockout threat — common fear-based social engineering.")

    if any(w in text_lower for w in ["urgent", "immediately", "act now", "24 hours", "48 hours", "expires soon"]):
        indicators.append("Urgency/fear tactic detected.")

    if any(w in text_lower for w in ["winner", "prize", "congratulations you", "free gift", "you have been selected"]):
        indicators.append("Lottery or prize scam tactic detected.")

    if any(w in text_lower for w in ["kyc", "aadhaar", "aadhar", "pan card", "tax refund", "income tax notice"]):
        indicators.append("Government or KYC impersonation pattern detected.")

    if found_urls:
        indicators.append(f"URLs found in screenshot: {', '.join(found_urls[:3])}")

    # ── Verdict ─────────────────────────────────────────────────────────────
    if risk >= 55:
        verdict = "High Risk — Likely Scam/Phishing"
    elif risk >= 25:
        verdict = "Medium Risk — Suspicious Content"
    else:
        verdict = "Low Risk — No Major Indicators"

    return {
        "text": extracted_text,
        "risk": risk,
        "verdict": verdict,
        "indicators": indicators,
        "found_urls": found_urls,
    }
