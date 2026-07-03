
import streamlit as st
import joblib

from ai_copilot import generate_ai_explanation
from email_ai_copilot import generate_email_intelligence

from email_analyzer import analyze_email
from feature_extractor import extract_features
from brand_detector import detect_brand
from threat_explainer import explain_threat
from website_analyzer import analyze_website
from email_url_scanner import extract_urls
from virustotal_scanner import scan_url_virustotal
from whois_checker import check_domain_age
from mitre_mapper import map_to_mitre

from history_manager import (
    save_scan,
    load_history,
    clear_history
)

from report_generator import generate_report
from qr_analyzer import analyze_qr
from image_analyzer import analyze_screenshot

# =====================================================
# LOAD MODEL
# =====================================================

model = joblib.load(
    "phishing_model.pkl"
)


# =====================================================
# PAGE CONFIG
# =====================================================

st.set_page_config(
    page_title="Phis-ShieldAI",
    page_icon="🛡️",
    layout="wide"
)
st.markdown("""
<style>

/* Sidebar radio options */
section[data-testid="stSidebar"] label p{
    font-size:22px !important;
    font-weight:800;
}

/* Sidebar heading */
section[data-testid="stSidebar"] h1,
section[data-testid="stSidebar"] h2,
section[data-testid="stSidebar"] h3{
    font-size:22px !important;
}

</style>
""", unsafe_allow_html=True)

st.title("🛡️ Phis-ShieldAI")

st.subheader(
    "AI-Powered Phishing Detection & Threat Intelligence Platform"
)

# =====================================================
# SIDEBAR
# =====================================================

analysis_mode = st.sidebar.radio(
    "Navigation",
    [
        "URL Analysis",
        "Email Analysis",
        "Screenshot Analysis",
        "QR Analysis",
        "Scan History"
    ]
)

# =====================================================
# HISTORY PAGE
# =====================================================

if analysis_mode == "Scan History":

    st.header("📜 Scan History")

    history = load_history()

    if history.empty:
        st.info("No scan history yet.")
    else:
        st.dataframe(
            history,
            use_container_width=True
        )

    st.divider()

    if st.button("🗑️ Clear All History", type="secondary"):
        clear_history()
        st.success("History cleared!")
        st.rerun()

    st.stop()
# =====================================================
# QR ANALYSIS
# =====================================================

if analysis_mode == "QR Analysis":

    st.header(
        "🔳 QR Code Phishing Detector"
    )

    uploaded_qr = st.file_uploader(
        "Upload QR Code Image",
        type=["png", "jpg", "jpeg"]
    )

    if uploaded_qr:

        file_path = uploaded_qr.name

        with open(
            file_path,
            "wb"
        ) as f:

            f.write(
                uploaded_qr.getbuffer()
            )

        extracted_url = analyze_qr(
            file_path
        )

        if extracted_url is None:

            st.error(
                "No QR Code detected."
            )

        else:

            st.success(
                "QR Code Detected"
            )

            st.write(
                f"Embedded Content: {extracted_url}"
            )

            # Add https if missing

            if not extracted_url.startswith(
                ("http://", "https://")
            ):

                extracted_url = (
                    "https://" + extracted_url
                )

            features = extract_features(
                extracted_url
            )

            prediction = model.predict(
                [features]
            )[0]

            probabilities = model.predict_proba(
                [features]
            )[0]

            confidence = round(
                max(probabilities) * 100,
                2
            )

            # Trusted Domain Check


            brand, similarity = detect_brand(
                extracted_url
            )

            # Risk Score

            risk = 0
            url_lower = extracted_url.lower()
            from urllib.parse import urlparse as _up
            import re as _re
            from brand_detector import _is_authoritative as _is_auth
            _parsed_qr = _up(extracted_url if "://" in extracted_url else "https://"+extracted_url)
            _netloc_raw = _parsed_qr.netloc.lower()
            _netloc = _netloc_raw[4:] if _netloc_raw.startswith("www.") else _netloc_raw
            _qr_trusted = _is_auth(_netloc)

            # Only add ML score if domain is not a known-trusted one
            if prediction == 1 and not _qr_trusted:
                risk += 40

            # Brand impersonation only meaningful if NOT the real domain
            if not _qr_trusted:
                if similarity > 85:
                    risk += 25
                elif similarity > 65:
                    risk += 15

            # Keyword scoring: use word-boundary matching, skip trusted domains
            if not _qr_trusted:
                _kw_high = ["otp","password","credential","signin","suspended","unlock"]
                _kw_med  = ["login","verify","secure","account","update","bank",
                            "wallet","confirm","reset","billing","recover"]
                _hits_high = sum(1 for w in _kw_high
                                 if _re.search(r'(?<![a-z0-9])' + w + r'(?![a-z0-9])', url_lower))
                _hits_med  = sum(1 for w in _kw_med
                                 if _re.search(r'(?<![a-z0-9])' + w + r'(?![a-z0-9])', url_lower))
                risk += min(_hits_high * 12 + max(_hits_med - 1, 0) * 6, 24)

            _qr_suspicious_tlds = [".xyz",".top",".click",".work",
                   ".loan",".gq",".ml",".cf",".tk",".pw",".cc",".su"]
            _qr_has_bad_tld = any(_netloc.endswith(t) for t in _qr_suspicious_tlds)
            if _qr_has_bad_tld:
                risk += 20

            if _re.search(r'\d{1,3}(\.\d{1,3}){3}', _netloc):
                risk += 20

            if _netloc.count("-") >= 2 and not _qr_trusted:
                risk += 10

            if _netloc.count(".") >= 3 and not _qr_trusted:
                risk += 10

            if len(extracted_url) > 75 and not _qr_trusted:
                risk += 5

            if "%" in extracted_url:
                risk += 5

            # Combo boost: brand impersonation + suspicious TLD
            if not _qr_trusted and similarity > 70 and _qr_has_bad_tld:
                risk += 15

            # Combo boost: brand impersonation + multiple hyphens
            if not _qr_trusted and similarity > 70 and _netloc.count("-") >= 2:
                risk += 10

            risk = min(risk, 100)

            save_scan(
                "QR",
                extracted_url,
                (
                    "Phishing"
                    if risk >= 75
                    else "Legitimate"
                ),
                risk
            )

            col1, col2 = st.columns(2)

            with col1:

                st.subheader(
                    "Detection Result"
                )

                if risk >= 75:

                    st.error(
                        f"⚠️ Phishing Detected ({confidence}%)"
                    )

                else:

                    st.success(
                        f"✅ Legitimate ({confidence}%)"
                    )

            with col2:

                st.subheader(
                    "Threat Risk Score"
                )

                st.progress(
                    min(risk, 100) / 100
                )

                st.metric(
                    "Risk Score",
                    f"{min(risk, 100)}/100"
                )

            st.metric(
                "Model Confidence",
                f"{confidence}%"
            )

            st.divider()

            st.subheader(
                "🎯 Brand Analysis"
            )

            if similarity > 85:

                st.error(
                    f"Brand Impersonation Detected: {brand.title()}"
                )

                st.write(
                    f"Similarity Score: {similarity}%"
                )

            elif similarity > 70:

                st.warning(
                    f"Possible Target Brand: {brand.title()}"
                )

                st.write(
                    f"Similarity Score: {similarity}%"
                )

            else:

                st.success(
                    "No brand impersonation detected."
                )

            st.divider()

            st.subheader(
                "🤖 AI Security Copilot"
            )

            reasons = []

            if prediction == 1 and not _qr_trusted:

                reasons.append(
                    "Machine Learning model flagged URL as phishing."
                )

            if similarity > 80 and not _qr_trusted:

                reasons.append(
                    "Strong brand impersonation detected."
                )

            ai_report = generate_ai_explanation(
                extracted_url,
                (
                    "Phishing"
                    if risk >= 75
                    else "Legitimate"
                ),
                risk,
                reasons,
                brand
            )

            st.success(
                f"🎯 Attack Type: {ai_report['attack_type']}"
            )

            st.warning(
                f"🏢 Likely Target Brand: {ai_report['brand']}"
            )

            st.write(
                "### 💥 Potential Impact"
            )

            for item in ai_report["impact"]:

                st.write(
                    "•",
                    item
                )

            st.write(
                "### 🕵️ Assessment"
            )

            st.info(
                ai_report["strategy"]
            )

            st.divider()

            st.subheader(
                "🛡 Recommendation"
            )

            if risk >= 70:

                st.error(
                    "HIGH RISK: Do not enter passwords, OTPs, or banking information."
                )

            elif risk >= 40:

                st.warning(
                    "MEDIUM RISK: Proceed with caution."
                )

            else:

                st.success(
                    "LOW RISK: QR destination appears safe."
                )

            report = generate_report(
                extracted_url,
                (
                    "Phishing"
                    if risk >= 75
                    else "Legitimate"
                ),
                risk,
                "\n".join(
                    reasons
                )
            )

            st.download_button(
                "📥 Download QR Security Report",
                report,
                file_name="qr_security_report.txt"
            )

    st.stop()
# =====================================================
# SCREENSHOT ANALYSIS
# =====================================================

if analysis_mode == "Screenshot Analysis":

    st.header(
        "🖼 Screenshot Scam Detector"
    )

    uploaded_file = st.file_uploader(
        "Upload Screenshot",
        type=["png", "jpg", "jpeg"]
    )

    if uploaded_file:

        file_path = uploaded_file.name

        with open(
            file_path,
            "wb"
        ) as f:

            f.write(
                uploaded_file.getbuffer()
            )

        result = analyze_screenshot(
            file_path
        )

        st.image(
            uploaded_file,
            use_container_width=True
        )

        st.subheader(
            "📄 Extracted Text"
        )

        st.text_area(
            "",
            result["text"],
            height=200
        )

        st.subheader(
            "🚨 Threat Assessment"
        )

        if result["risk"] >= 50:

            st.error(
                f"{result['verdict']} ({result['risk']}/100)"
            )

        elif result["risk"] >= 20:

            st.warning(
                f"{result['verdict']} ({result['risk']}/100)"
            )

        else:

            st.success(
                f"{result['verdict']} ({result['risk']}/100)"
            )

        st.subheader(
            "🤖 AI Findings"
        )

        if result["indicators"]:

            for item in result["indicators"]:

                st.write(
                    "•",
                    item
                )

        else:

            st.write(
                "No suspicious indicators found."
            )

        save_scan(
            "Screenshot",
            uploaded_file.name,
            result["verdict"],
            result["risk"]
        )

        report = generate_report(
            uploaded_file.name,
            result["verdict"],
            result["risk"],
            "\n".join(
                result["indicators"]
            )
        )

        st.download_button(
            "📥 Download Screenshot Report",
            report,
            file_name="screenshot_report.txt"
        )

    st.stop()
# =====================================================
# EMAIL ANALYSIS
# =====================================================

if analysis_mode == "Email Analysis":

    email_text = st.text_area(
        "Paste Email Content",
        height=300,
        placeholder="Paste suspicious email here..."
    )

    if st.button("Analyze Email"):

        if not email_text.strip():

            st.warning(
                "Please paste email content."
            )

            st.stop()

        result = analyze_email(
            email_text
        )

        prediction = result["prediction"]

        confidence = result[
            "confidence"
        ]

        save_scan(
            "Email",
            email_text[:100],
            (
                "Phishing"
                if prediction == 1
                else "Legitimate"
            ),
            confidence
        )

        st.subheader(
            "📧 Email Analysis Result"
        )

        if prediction == 1:

            st.error(
                f"⚠️ Phishing Email Detected ({confidence}%)"
            )

        else:

            st.success(
                f"✅ Legitimate Email ({confidence}%)"
            )

        st.progress(
            min(
                int(confidence),
                100
            )
        )

        st.metric(
            "Model Confidence",
            f"{confidence}%"
        )

        st.divider()

        st.subheader(
            "🔗 URLs Found"
        )

        urls = extract_urls(
            email_text
        )

        if urls:

            for detected_url in urls:

                st.code(
                    detected_url
                )

        else:

            st.write(
                "No URLs detected."
            )

        st.divider()

        st.subheader(
            "🔍 Embedded URL Analysis"
        )

        if urls:

            for found_url in urls:

                st.write(
                    f"Analyzing: {found_url}"
                )

                try:

                    features = (
                        extract_features(
                            found_url
                        )
                    )

                    url_prediction = (
                        model.predict(
                            [features]
                        )[0]
                    )

                    if url_prediction == 1:

                        st.error(
                            "⚠️ Suspicious URL Detected"
                        )

                    else:

                        st.success(
                            "✅ URL Appears Safe"
                        )

                except:

                    st.warning(
                        "Unable to analyze URL."
                    )

        else:

            st.write(
                "No URLs available for analysis."
            )

        st.divider()

        st.subheader(
            "🤖 Threat Indicators"
        )

        if result["reasons"]:

            # Keyword reasons alag group karo
            keyword_reasons = [r for r in result["reasons"] if r.startswith("Contains phishing keyword:")]
            other_reasons   = [r for r in result["reasons"] if not r.startswith("Contains phishing keyword:")]

            # Keywords ek hi line mein dikhao
            if keyword_reasons:
                keywords_found = [r.replace("Contains phishing keyword: ", "").strip("'") for r in keyword_reasons]
                st.write("• Phishing keywords found:", ", ".join(f"`{k}`" for k in keywords_found))

            # Baaki reasons alag alag
            for reason in other_reasons:
                st.write("•", reason)

        else:

            st.write(
                "No suspicious indicators found."
            )

        st.divider()

        st.subheader(
            "🤖 AI Email Intelligence"
        )

        email_ai = generate_email_intelligence(
            prediction,
            confidence,
            result["reasons"],
            urls
        )

        st.info(
            f"""
Threat Level: {email_ai['threat_level']}

Summary:
{email_ai['summary']}

Likely Attacker Goal:
{email_ai['attacker_goal']}

URLs Found:
{email_ai['url_count']}
"""
        )

        st.divider()

        st.subheader(
            "🛡 Recommendation"
        )

        if prediction == 1:

            st.error(
                "Do not click links or provide credentials from this email."
            )

        else:

            st.success(
                "Email appears legitimate according to the detection system."
            )

        report = generate_report(
            "Email Analysis",
            (
                "Phishing"
                if prediction == 1
                else "Legitimate"
            ),
            confidence,
            "\n".join(
                result["reasons"]
            )
        )

        st.download_button(
            "📥 Download Email Security Report",
            report,
            file_name="email_security_report.txt"
        )


# =====================================================
# URL ANALYSIS
# =====================================================

elif analysis_mode == "URL Analysis":

    url = st.text_input(
        "Enter URL",
        placeholder="https://amaz0n-login-security.xyz"
    )

    if st.button("Analyze URL"):

        if not url.strip():

            st.warning(
                "Please enter a URL."
            )

            st.stop()

        features = extract_features(
            url
        )

        prediction = model.predict(
            [features]
        )[0]

        probabilities = model.predict_proba(
            [features]
        )[0]

        confidence = round(
            max(probabilities) * 100,
            2
        )


        brand, similarity = detect_brand(
            url
        )

        website_info = analyze_website(
            url
        )

        ssl_enabled = website_info[
            "ssl"
        ]

        page_title = website_info[
            "title"
        ]

        reasons = explain_threat(
            prediction,
            similarity,
            ssl_enabled,
            url,
            page_title
        )

        risk = 0
        url_lower = url.lower()
        from urllib.parse import urlparse as _up
        import re as _re
        from brand_detector import _is_authoritative as _is_auth
        _parsed_url = _up(url if "://" in url else "https://"+url)
        _netloc_raw = _parsed_url.netloc.lower()
        _netloc = _netloc_raw[4:] if _netloc_raw.startswith("www.") else _netloc_raw
        _url_trusted = _is_auth(_netloc)

        # ML score: suppress for known-trusted domains
        if prediction == 1 and not _url_trusted:
            risk += 40

        # Brand impersonation: skip if domain is genuinely the brand's own
        if not _url_trusted:
            if similarity > 85:
                risk += 25
            elif similarity > 65:
                risk += 15

        if not ssl_enabled and not _url_trusted:
            risk += 10

        # Keyword scoring: word-boundary match, skip trusted domains
        if not _url_trusted:
            _kw_high = ["otp","password","credential","signin","suspended","unlock"]
            _kw_med  = ["login","verify","secure","account","update","bank",
                        "wallet","confirm","reset","billing","recover"]
            _hits_high = sum(1 for w in _kw_high
                             if _re.search(r'(?<![a-z0-9])' + w + r'(?![a-z0-9])', url_lower))
            _hits_med  = sum(1 for w in _kw_med
                             if _re.search(r'(?<![a-z0-9])' + w + r'(?![a-z0-9])', url_lower))
            risk += min(_hits_high * 12 + max(_hits_med - 1, 0) * 6, 24)

        _suspicious_tlds = [".xyz",".top",".click",".work",
               ".loan",".gq",".ml",".cf",".tk",".pw",".cc",".su"]
        _has_suspicious_tld = any(_netloc.endswith(t) for t in _suspicious_tlds)
        if _has_suspicious_tld:
            risk += 20

        if _re.search(r'\d{1,3}(\.\d{1,3}){3}', _netloc):
            risk += 20

        if _netloc.count("-") >= 2 and not _url_trusted:
            risk += 10

        if _netloc.count(".") >= 3 and not _url_trusted:
            risk += 10

        # Combo boost: brand impersonation + suspicious TLD is a very strong phishing signal
        if not _url_trusted and similarity > 70 and _has_suspicious_tld:
            risk += 15

        # Combo boost: brand impersonation + multiple hyphens (typosquatting pattern)
        if not _url_trusted and similarity > 70 and _netloc.count("-") >= 2:
            risk += 10

        if len(url) > 75 and not _url_trusted:
            risk += 5

        if "%" in url:
            risk += 5

        risk = min(risk, 100)

        save_scan(
            "URL",
            url,
            (
                "Phishing"
                if risk >= 75
                else "Legitimate"
            ),
            risk
        )

        col1, col2 = st.columns(2)

        with col1:

            st.subheader(
                "Detection Result"
            )

            if risk >= 75:

                st.error(
                    f"⚠️ Phishing Detected ({confidence}%)"
                )

            else:

                st.success(
                    f"✅ Legitimate ({confidence}%)"
                )

        with col2:

            st.subheader(
                "Threat Risk Score"
            )

            st.progress(
                min(risk, 100) / 100
            )

            st.metric(
                "Risk Score",
                f"{min(risk, 100)}/100"
            )

        st.divider()

        st.subheader(
            "🎯 Brand Analysis"
        )

        if similarity > 85:

            st.error(
                f"Brand Impersonation Detected: {brand.title()}"
            )

            st.write(
                f"Similarity Score: {similarity}%"
            )

        elif similarity > 70:

            st.warning(
                f"Possible Target Brand: {brand.title()}"
            )

            st.write(
                f"Similarity Score: {similarity}%"
            )

        else:

            st.success(
                "No brand impersonation detected."
            )

        st.divider()

        st.subheader(
            "🔒 SSL Analysis"
        )

        if ssl_enabled:

            st.success(
                "HTTPS / SSL Protection Enabled"
            )

        else:

            st.error(
                "No SSL Protection Detected"
            )

        st.divider()

        st.subheader(
            "🌐 Website Content Analysis"
        )

        if website_info["reachable"]:

            if page_title:

                st.write(
                    f"Page Title: {page_title}"
                )

            else:

                st.info(
                    "Website reachable but no page title found."
                )

        else:

            st.error(
                "Website is unreachable or does not exist."
            )

        st.divider()

        st.subheader(
            "🤖 AI Security Copilot"
        )

        ai_report = generate_ai_explanation(
            url,
            (
                "Phishing"
                if risk >= 75
                else "Legitimate"
            ),
            risk,
            reasons,
            brand
        )

        st.success(
            f"🎯 Attack Type: {ai_report['attack_type']}"
        )

        st.warning(
            f"🏢 Likely Target Brand: {ai_report['brand']}"
        )

        st.write(
            "### 💥 Potential Impact"
        )

        for item in ai_report["impact"]:

            st.write(
                "•",
                item
            )

        st.write(
            "### 🕵️ Assessment"
        )

        st.info(
            ai_report["strategy"]
        )

        st.divider()

        st.subheader(
            "🛡 Recommendation"
        )

        if risk >= 70:

            st.error(
                "HIGH RISK: Do not enter passwords, OTPs, or banking information."
            )

        elif risk >= 40:

            st.warning(
                "MEDIUM RISK: Proceed with caution."
            )

        else:

            st.success(
                "LOW RISK: Website appears safe."
            )

        report = generate_report(
            url,
            (
                "Phishing"
                if risk >= 75
                else "Legitimate"
            ),
            risk,
            "\n".join(
                reasons
            )
        )
        st.divider()

        st.subheader("🦠 VirusTotal Scan")
        with st.spinner("Scanning with 70+ antivirus engines..."):
            vt_result = scan_url_virustotal(url)
        if vt_result:
            col_a, col_b, col_c = st.columns(3)
            col_a.metric("🔴 Malicious Engines", vt_result["malicious"])
            col_b.metric("🟡 Suspicious", vt_result["suspicious"])
            col_c.metric("🟢 Clean Engines", vt_result["harmless"])
            if vt_result["verdict"] == "Dangerous":
                st.error(f"⚠️ {vt_result['malicious']}/{vt_result['total']} engines flagged this URL as malicious!")
            elif vt_result["verdict"] == "Suspicious":
                st.warning(f"🟡 {vt_result['suspicious']} engines marked this suspicious.")
            else:
                st.success("✅ No engines flagged this URL.")
        else:
            st.info("VirusTotal scan unavailable.")

        st.divider()

        st.subheader("🌐 WHOIS Domain Intelligence")
        whois_result = check_domain_age(url)
        if whois_result:
            col_x, col_y = st.columns(2)
            col_x.metric("📅 Domain Age", f"{whois_result['age_days']} days" if whois_result['age_days'] else "Unknown")
            col_y.metric("🏢 Registrar", whois_result["registrar"] or "Unknown")
            st.write(f"**Created:** {whois_result.get('created', 'Unknown')}")
            st.write(f"**Country:** {whois_result['country']}")
            if whois_result["age_days"] is None:
                st.warning("⚠️ WHOIS data hidden — free/disposable TLDs (.ml, .tk, .xyz) often hide registration info to avoid tracking. This is itself a phishing indicator.")
            else:
                st.info(whois_result["verdict"])
        else:
            st.warning("⚠️ WHOIS data unavailable — domain may be using a privacy-protected or disposable registration.")

        st.divider()

        st.subheader("🎯 MITRE ATT&CK Threat Mapping")
        mitre_techniques = map_to_mitre(url, similarity, risk, reasons)
        if mitre_techniques:
            for t in mitre_techniques:
                with st.expander(f"🔴 {t['id']} — {t['name']}"):
                    st.write(f"**Tactic:** {t['tactic']}")
                    st.write(f"**Detail:** {t['detail']}")
                    st.write(f"**Known Threat Groups:** {t['groups']}")
        else:
            st.success("No MITRE techniques matched — URL appears safe.")

        st.download_button(
            "📥 Download Security Report",
            report,
            file_name="security_report.txt"
        )

#TEST

# Phishing (high risk):

# https://amazon-security-alert-update.tk/signin
# https://sbi-netbanking-verify.ml/login/otp
# https://paypal-secure-login.xyz/verify
# Legitimate (clean hone chahiye):

#Legitimate

# https://github.com
# https://wikipedia.org
# https://stackoverflow.com
# https://accounts.google.com/signin
# https://www.amazon.com/account

# Subject: Amazon Security Alert
# Your account has been suspended.
# Verify your password immediately:
# https://amaz0n-login-security.xyz
# Failure to act within 24 hours will result in permanent account closure.


# Subject: Project Meeting Reminder
# Hi Team
# This is a reminder that our project review meeting is scheduled for tomorrow at 10:00 AM.
# Please bring your progress updates.
# Best Regards
# Project Coordinator

# Subject: Congratulations! You Have Been Selected as a Winner
# Dear User,
# You have been selected as the lucky winner of Rs. 15,00,000 in our annual draw.
# Claim your prize here: http://lucky-winner-claim.tk/reward
# To process your reward, confirm your identity and pay a small processing fee of Rs. 500.
# Regards,
# Prize Distribution Team