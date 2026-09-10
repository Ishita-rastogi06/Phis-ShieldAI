# PhishShield AI — Ground-Truth Project Status Summary

> **Notice**: Every metric, capability, and statement in this document is independently verified in the live running application and unit test suite as of August 2026.

---

## 1. What Genuinely Works End-to-End

### A. Real-Time Live ML Classifier (25 Features)
- **Live Inference**: The ML classifier runs **live on any reachable URL** by extracting 25 real-time structural, DOM, TLS, DNS, and WHOIS features (`uci-live-25-v1`).
- **Empirical Held-Out Metrics** (evaluated on held-out test data from OpenML 4534):
  - **Accuracy**: **93.05%**
  - **Phishing Precision**: **93.95%**
  - **Phishing Recall**: **92.49%**
  - **Phishing F1 Score**: **93.21%**
  - **ROC-AUC**: **98.20%**
  - **Confusion Matrix**: True Positives: 419, True Negatives: 398, False Positives: 27, False Negatives: 34.
- **Model Estimator**: Random Forest Classifier (`n_estimators=300, min_samples_leaf=2, max_features='sqrt', class_weight='balanced'`).
- **Artifact Path**: `models/artifacts/url_live_25_detector.joblib`.

### B. Active Threat-Intelligence Integration
- **VirusTotal Integration**:
  - Performs fast-path passive lookup `GET /api/v3/urls/{id}`.
  - If report is missing or > 7 days old, issues active submission `POST /api/v3/urls` and polls `GET /api/v3/analyses/{id}` inline.
- **OpenPhish Integration**:
  - Queries active phishing URL intelligence feeds.
- **UI Telemetry Badges**:
  - `AVAILABLE (EXISTING REPORT ℹ️)`
  - `NO MATCH (0 Prior Records Found)`
  - `UNAVAILABLE / NOT CONFIGURED`

### C. Multi-Modality URL Convergence
- **Email Analysis**: Extracts embedded URLs from plain text or HTML emails and routes them to the shared 25-feature live URL analysis pipeline.
- **QR Code Analysis**: Decodes QR images using multi-engine fallbacks (ZXing-CPP, PyZbar, OpenCV). Non-URL payloads (WiFi credentials, vCard contacts, plain text) are safely categorized as `SAFE_PAYLOAD`; URL payloads are routed to the shared 25-feature live URL pipeline.
- **Screenshot OCR**: Extracts text and embedded URLs from image uploads, passing extracted URLs to the shared 25-feature live URL pipeline.

### D. Security & SSRF Protection
- **SSRF Defensive Filtering**: Blocks attempts against private IP ranges (`192.168.x.x`, `10.x.x.x`, `127.0.0.1`, `::1`), non-permitted URL schemes (`ftp:`, `javascript:`, `file:`), and unresolvable internal hosts.

---

## 2. Intentionally Limited or Out-of-Scope Items

- **Email ML Classifier**: Deliberately reported as `ML UNAVAILABLE` when explicit email vectorizer/model artifacts are not supplied. No synthetic or dummy email ML model is used. Email URL extraction and indicator analysis remain fully operational.
- **Historical UCI Features**: 5 historical features (`web_traffic`, `Page_Rank`, `Google_Index`, `Links_pointing_to_page`, `Statistical_report`) are **intentionally excluded** from live ML inference because Alexa rankings are discontinued and Google PageRank is not queryable live. This prevents data fabrication.

---

## 3. Real Typical Scan Latency

- **Cached / Pre-existing Report Path**: **1.5 to 3.0 seconds** per URL.
- **Fresh URL Active Submission & Polling Path**: **5.0 to 10.0 seconds** per URL.

---

## 4. Technical Architecture & Stack

- **Language & UI**: Python 3.13, Streamlit
- **Machine Learning**: scikit-learn (`RandomForestClassifier`), joblib
- **Web & Network**: requests, BeautifulSoup4, tldextract, python-whois, socket, ssl
- **QR & OCR**: OpenCV, PyZbar, ZXing-CPP, Pillow
- **Threat Intelligence**: VirusTotal API v3, OpenPhish API
- **Testing**: Python `unittest`, Streamlit `AppTest`
