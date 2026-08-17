# URL model evaluation

## Dataset

- Source: recovered `dataset.csv` (UCI Phishing Websites schema)
- Original rows: 11055
- Exact duplicate rows removed before splitting: 5206
- Rows evaluated after deduplication: 5849
- Label mapping: `Result=-1` is phishing (`1`); `Result=1` is legitimate (`0`).
- Dataset checksum (SHA-256): `e20bf913b6c2e669f4e875e5d223be2542cc7c79a7b62d284ae9d9627c3d9678`

## Model and preprocessing

The artifact uses the validation-selected `random_forest` classifier
and all 30 UCI features, in this exact order:
`having_IP_Address, URL_Length, Shortining_Service, having_At_Symbol, double_slash_redirecting, Prefix_Suffix, having_Sub_Domain, SSLfinal_State, Domain_registeration_length, Favicon, port, HTTPS_token, Request_URL, URL_of_Anchor, Links_in_tags, SFH, Submitting_to_email, Abnormal_URL, Redirect, on_mouseover, RightClick, popUpWidnow, Iframe, age_of_domain, DNSRecord, web_traffic, Page_Rank, Google_Index, Links_pointing_to_page, Statistical_report`.

At inference, URL, webpage, DNS/WHOIS, and configured external-intelligence
providers collect this same schema. If any required source is unavailable,
inference fails clearly rather than filling a feature with a made-up value.

## Split strategy

Duplicate rows were removed before a stratified 70%/15%/15% train/validation/test
split. The validation set selected the estimator; the test set below was held out
until final evaluation. Random seed: 42.

## Held-out test metrics

| Metric | Value |
| --- | ---: |
| Accuracy | 94.08% |
| Phishing precision | 95.06% |
| Phishing recall | 93.38% |
| Phishing F1 | 94.21% |
| ROC-AUC | 98.87% |

### Confusion matrix

| Actual / predicted | Legitimate | Phishing |
| --- | ---: | ---: |
| Legitimate | 403 | 22 |
| Phishing | 30 | 423 |

False negatives: 30; false positives: 22.

## Limitations

This is a historical, feature-engineered benchmark. Its performance does not
guarantee protection from new phishing campaigns. The model is one signal; the
application also presents separate brand and threat-intelligence signals.
