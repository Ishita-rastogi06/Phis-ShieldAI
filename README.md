# 🛡️ Phis-ShieldAI — Phishing Detection Tool

An AI-powered phishing detection system that analyzes URLs, emails, screenshots, and QR codes to identify phishing threats in real time.

---

## 🚀 Features

- **URL Scanner** — Detects phishing URLs using a trained ML model + VirusTotal API
- **Email Analyzer** — Scans email content for phishing indicators
- **Brand Detection** — Identifies impersonated brands (Amazon, PayPal, SBI, etc.)
- **Screenshot Analyzer** — Analyzes webpage screenshots for visual phishing clues
- **QR Code Scanner** — Extracts and scans URLs embedded in QR codes
- **MITRE ATT&CK Mapping** — Maps detected threats to MITRE framework tactics
- **AI Copilot** — Provides plain-English threat explanations using AI
- **Threat History** — Saves and displays scan history

---

## 🛠️ Tech Stack

- **Frontend/UI** — Streamlit
- **ML Models** — scikit-learn (trained on phishing datasets)
- **External APIs** — VirusTotal, WHOIS
- **Language** — Python 3.x

---

## 📦 Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/Ishita-rastogi06/Phis-ShieldAI.git
   cd Phis-ShieldAI
   ```

2. **Create a virtual environment** (recommended)
   ```bash
   python -m venv venv
   source venv/bin/activate      # Linux/macOS
   venv\Scripts\activate         # Windows
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Set up API keys**

   Create a `.env` file in the project root:
   ```
   VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
   ```

5. **Run the app**
   ```bash
   streamlit run app.py
   ```

---

## 📁 Project Structure

```
Phis-ShieldAI/
├── app.py                    # Main Streamlit app
├── ai_copilot.py             # AI explanation generator
├── email_ai_copilot.py       # Email-specific AI analysis
├── email_analyzer.py         # Email phishing analyzer
├── feature_extractor.py      # URL feature extraction
├── brand_detector.py         # Brand impersonation detector
├── threat_explainer.py       # Threat explanation module
├── website_analyzer.py       # Website content analyzer
├── image_analyzer.py         # Screenshot analyzer
├── qr_analyzer.py            # QR code scanner
├── mitre_mapper.py           # MITRE ATT&CK mapper
├── virustotal_scanner.py     # VirusTotal API integration
├── whois_checker.py          # WHOIS/domain age checker
├── history_manager.py        # Scan history manager
├── report_generator.py       # Report generation
├── train.py                  # URL model training script
├── train_email.py            # Email model training script
├── requirements.txt          # Python dependencies
└── README.md
```

---

## 🧪 Test URLs

**Phishing (should flag as high risk):**
- `https://amazon-security-alert-update.tk/signin`
- `https://sbi-netbanking-verify.ml/login/otp`
- `https://paypal-secure-login.xyz/verify`

**Legitimate (should be clean):**
- `https://github.com`
- `https://wikipedia.org`
- `https://accounts.google.com/signin`

---

## ⚠️ Disclaimer

This tool is built for **educational and research purposes only**. Do not use it to scan URLs or emails without proper authorization.

---

## 👤 Author

Made by Ishita Rastogi  
GitHub: [@Ishita-rastogi06](https://github.com/Ishita-rastogi06)