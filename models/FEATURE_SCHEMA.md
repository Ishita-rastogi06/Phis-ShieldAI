# Live 25-Feature UCI Schema

The active ML model (`url_live_25_detector.joblib`) uses schema version `uci-live-25-v1`.

5 historical UCI features (`web_traffic`, `Page_Rank`, `Google_Index`, `Links_pointing_to_page`, and `Statistical_report`) were dropped because they cannot be collected faithfully for live URLs. Only signals that can be genuinely extracted in real time from the target host, DOM, TLS certificate, DNS, and WHOIS are used.

The canonical platform verdict combines this 25-feature Random Forest classifier with independent evidence from website inspection, TLS, DNS, WHOIS, brand detection, VirusTotal, and OpenPhish.
