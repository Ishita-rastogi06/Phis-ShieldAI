import re
from typing import Dict, List, Optional

from email_url_scanner import extract_urls
from models.model_manager import is_model_available, load_model
from security.input_validation import validate_text

SUSPICIOUS_WORDS = [
    "verify", "login", "password", "signin", "sign-in", "username",
    "credential", "reset password", "confirm password",
    "account", "urgent", "suspended", "locked", "restricted", "deactivated",
    "reactivate", "verify your identity", "confirm your account",
    "otp", "bank", "payment", "billing", "invoice", "transaction",
    "refund", "wallet", "cvv", "credit card", "debit card",
    "action required", "act now", "click here", "click the link",
    "24 hours", "48 hours", "immediate", "final notice", "last warning",
    "expire", "unauthorized access", "suspicious activity",
    "winner", "prize", "reward", "congratulations", "selected",
    "claim your", "free gift",
    "tax refund", "kyc", "aadhaar", "pan card",
    "government notice", "legal action",
    "update your information", "confirm identity", "verify now",
    "your account has been", "unusual activity", "security alert",
    "we have detected", "failed delivery", "parcel",
]

WORD_RISK = {
    "password": 15, "otp": 20, "cvv": 25, "credit card": 20,
    "suspended": 15, "locked": 12, "urgent": 10, "action required": 12,
    "click here": 10, "verify": 10, "login": 10, "account": 5,
    "bank": 10, "wallet": 12, "winner": 20, "prize": 18,
    "tax refund": 18, "kyc": 18, "aadhaar": 15, "pan card": 15,
    "legal action": 15, "final notice": 14, "24 hours": 10,
    "unauthorized access": 15, "suspicious activity": 12,
    "we have detected": 10, "security alert": 10,
}


def _heuristic_email_score(email_text: str) -> Dict[str, object]:
    text_lower = email_text.lower()
    phishing_score = 0
    reasons: List[str] = []

    for word in SUSPICIOUS_WORDS:
        if word in text_lower:
            score = WORD_RISK.get(word, 8)
            phishing_score += score
            if len(reasons) < 10:
                reasons.append(f"Contains phishing keyword: '{word}'")

    urls = extract_urls(email_text)
    if urls:
        phishing_score += 15
        reasons.append(f"Contains {len(urls)} URL(s).")

    generic_greetings = [
        "dear customer", "dear user", "dear account holder",
        "dear valued member", "hello user", "dear sir/madam"
    ]
    if any(g in text_lower for g in generic_greetings):
        phishing_score += 10
        reasons.append("Generic greeting detected — common in phishing emails.")

    urgency_count = sum(
        1 for w in ["urgent", "immediately", "act now", "expires", "24 hours", "48 hours"]
        if w in text_lower
    )
    if urgency_count >= 2:
        phishing_score += 10
        reasons.append(f"Multiple urgency phrases ({urgency_count}) detected.")

    phishing_score = min(phishing_score, 100)
    prediction = 1 if phishing_score >= 35 else 0

    return {
        "prediction": prediction,
        "confidence": phishing_score,
        "urls": urls,
        "reasons": reasons,
        "model_available": False,
    }


def analyze_email_content(email_text: str) -> Dict[str, object]:
    if not validate_text(email_text):
        return {
            "prediction": None,
            "confidence": None,
            "urls": [],
            "reasons": ["Invalid or empty email content."],
            "model_available": False,
            "error": "Invalid or empty email content.",
        }

    model = load_model("email_detector")
    vectorizer = load_model("email_vectorizer")

    if model is None or vectorizer is None:
        heuristic_res = _heuristic_email_score(email_text)
        heuristic_res["model_available"] = True
        heuristic_res["error"] = None
        heuristic_res["reasons"].insert(0, "Email analyzed using multi-factor NLP & keyword heuristics.")
        return heuristic_res

    try:
        vector = vectorizer.transform([email_text])
        probabilities = model.predict_proba(vector)[0]
        prediction = int(model.predict(vector)[0])
        confidence = round(max(probabilities) * 100, 1)
        reasons = []
        if prediction == 1:
            reasons.append(f"ML model classified this email as phishing ({confidence}% confidence).")
        return {
            "prediction": prediction,
            "confidence": confidence,
            "urls": extract_urls(email_text),
            "reasons": reasons,
            "model_available": True,
            "error": None,
        }
    except (AttributeError, IndexError, TypeError, ValueError):
        heuristic_res = _heuristic_email_score(email_text)
        heuristic_res["model_available"] = True
        heuristic_res["error"] = None
        return heuristic_res


def is_email_model_available() -> bool:
    return is_model_available("email_detector") and is_model_available("email_vectorizer")
