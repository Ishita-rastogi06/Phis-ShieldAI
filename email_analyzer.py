import re
import joblib

try:
    model = joblib.load("email_model.pkl")
    vectorizer = joblib.load("email_vectorizer.pkl")
    ML_AVAILABLE = True
except Exception:
    ML_AVAILABLE = False

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
    "income tax", "tax refund", "kyc", "aadhaar", "pan card",
    "epfo", "irctc", "government notice", "legal action",
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

def analyze_email(email_text):
    phishing_score = 0
    reasons = []
    text_lower = email_text.lower()

    # ML model scoring
    if ML_AVAILABLE:
        try:
            vec = vectorizer.transform([email_text])
            ml_prediction = model.predict(vec)[0]
            ml_prob = model.predict_proba(vec)[0]
            ml_conf = round(max(ml_prob) * 100, 1)
            if ml_prediction == 1:
                phishing_score += 40
                reasons.append(f"ML model classified email as phishing ({ml_conf}% confidence).")
        except Exception:
            pass

    # Keyword scoring
    for word in SUSPICIOUS_WORDS:
        if word.lower() in text_lower:
            score = WORD_RISK.get(word.lower(), 8)
            phishing_score += score
            reasons.append(f"Contains phishing keyword: '{word}'")

    # URL presence
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', email_text)
    if urls:
        phishing_score += 15
        reasons.append(f"Contains {len(urls)} URL(s).")

    # Generic greeting
    generic_greetings = ["dear customer", "dear user", "dear account holder",
                         "dear valued member", "hello user", "dear sir/madam"]
    if any(g in text_lower for g in generic_greetings):
        phishing_score += 10
        reasons.append("Generic non-personalized greeting — typical of mass phishing.")

    # Excessive urgency
    urgency_count = sum(1 for w in ["urgent", "immediately", "act now", "expires", "24 hours", "48 hours"] if w in text_lower)
    if urgency_count >= 2:
        phishing_score += 10
        reasons.append(f"Multiple urgency phrases ({urgency_count}) detected — pressure tactic.")

    confidence = min(phishing_score, 100)
    prediction = 1 if confidence >= 35 else 0

    return {
        "prediction": prediction,
        "confidence": confidence,
        "urls": urls,
        "reasons": reasons
    }