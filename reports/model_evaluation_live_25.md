# Live 25-Feature URL Model Evaluation

## Overview

- **Schema Version**: `uci-live-25-v1`
- **Feature Count**: 25 live-collectible features (dropped 5 uncollectible historical features)
- **Selected Estimator**: `random_forest`
- **Dataset**: UCI Phishing Websites (OpenML ID 4534)
- **Original Rows**: 11055
- **Rows Evaluated After Deduplication**: 5849

## Live-Collectible Features (25)

having_IP_Address, URL_Length, Shortining_Service, having_At_Symbol, double_slash_redirecting, Prefix_Suffix, having_Sub_Domain, SSLfinal_State, Domain_registeration_length, Favicon, port, HTTPS_token, Request_URL, URL_of_Anchor, Links_in_tags, SFH, Submitting_to_email, Abnormal_URL, Redirect, on_mouseover, RightClick, popUpWidnow, Iframe, age_of_domain, DNSRecord

## Validation Performance Comparison

| Model | Accuracy | Precision | Recall | F1 Score | ROC-AUC |
| --- | ---: | ---: | ---: | ---: | ---: |
| Random Forest | 92.94% | 94.13% | 92.05% | 93.08% | 98.23% |
| Gradient Boosting | 92.60% | 94.09% | 91.39% | 92.72% | 98.17% |
| Logistic Regression | 90.66% | 92.06% | 89.62% | 90.83% | 96.81% |

## Final Held-Out Test Metrics (random_forest)

| Metric | Value |
| --- | ---: |
| Accuracy | 93.05% |
| Phishing Precision | 93.95% |
| Phishing Recall | 92.49% |
| Phishing F1 Score | 93.21% |
| ROC-AUC | 98.20% |

### Confusion Matrix

| Actual / Predicted | Legitimate (0) | Phishing (1) |
| --- | ---: | ---: |
| Legitimate (0) | 398 | 27 |
| Phishing (1) | 34 | 419 |

True Positives: 419, True Negatives: 398, False Positives: 27, False Negatives: 34.
