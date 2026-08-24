# Phis-ShieldAI Live 25-Feature URL Model Evaluation

## Overview

- **Schema Version**: `uci-live-25-v1`
- **Feature Count**: 25 live-collectible features (dropped 5 uncollectible historical features: `web_traffic`, `Page_Rank`, `Google_Index`, `Links_pointing_to_page`, `Statistical_report`)
- **Selected Estimator**: `random_forest` (RandomForestClassifier, 300 estimators)
- **Dataset**: UCI Phishing Websites (OpenML ID 4534)
- **Original Rows**: 11,055
- **Deduplicated Rows**: 5,849

## Live-Collectible Features (25)

1. `having_IP_Address`
2. `URL_Length`
3. `Shortining_Service`
4. `having_At_Symbol`
5. `double_slash_redirecting`
6. `Prefix_Suffix`
7. `having_Sub_Domain`
8. `SSLfinal_State`
9. `Domain_registeration_length`
10. `Favicon`
11. `port`
12. `HTTPS_token`
13. `Request_URL`
14. `URL_of_Anchor`
15. `Links_in_tags`
16. `SFH`
17. `Submitting_to_email`
18. `Abnormal_URL`
19. `Redirect`
20. `on_mouseover`
21. `RightClick`
22. `popUpWidnow`
23. `Iframe`
24. `age_of_domain`
25. `DNSRecord`

## Validation Performance Comparison

| Model | Accuracy | Precision | Recall | F1 Score | ROC-AUC |
| --- | ---: | ---: | ---: | ---: | ---: |
| **Random Forest** | **92.94%** | **94.13%** | **92.05%** | **93.08%** | **98.23%** |
| Gradient Boosting | 92.60% | 94.09% | 91.39% | 92.72% | 98.17% |
| Logistic Regression | 90.66% | 92.06% | 89.62% | 90.83% | 96.81% |

## Final Held-Out Test Metrics (`random_forest`)

| Metric | Value |
| --- | ---: |
| **Accuracy** | **93.05%** |
| **Phishing Precision** | **93.95%** |
| **Phishing Recall** | **92.49%** |
| **Phishing F1 Score** | **93.21%** |
| **ROC-AUC** | **98.20%** |

### Confusion Matrix

| Actual / Predicted | Legitimate (0) | Phishing (1) |
| --- | ---: | ---: |
| **Legitimate (0)** | 398 | 27 |
| **Phishing (1)** | 34 | 419 |

True Positives: 419, True Negatives: 398, False Positives: 27, False Negatives: 34.
