def generate_email_intelligence(
    prediction,
    confidence,
    reasons,
    urls
):

    if prediction == 1:

        threat_level = "High"

        summary = (
            "The email exhibits multiple phishing indicators "
            "including urgency tactics, credential harvesting "
            "language, and suspicious links."
        )

        attacker_goal = (
            "Likely attempting to obtain passwords, "
            "financial information, or account access."
        )

    else:

        threat_level = "Low"

        summary = (
            "The email does not display significant phishing "
            "characteristics."
        )

        attacker_goal = (
            "No malicious intent detected."
        )

    return {
        "threat_level": threat_level,
        "summary": summary,
        "attacker_goal": attacker_goal,
        "url_count": len(urls)
    }