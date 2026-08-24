"""Train the 25-feature Live URL classifier from OpenML / UCI dataset.

This script trains models on ONLY the 25 features collectible in real time for any live URL,
excluding the 5 historical features (web_traffic, Page_Rank, Google_Index, Links_pointing_to_page, Statistical_report).
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
from sklearn.datasets import fetch_openml
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import train_test_split

from models.model_config import ARTIFACTS_DIR

RANDOM_STATE = 42
FEATURE_SCHEMA_VERSION_25 = "uci-live-25-v1"

LIVE_25_FEATURE_NAMES = [
    "having_IP_Address", "URL_Length", "Shortining_Service", "having_At_Symbol",
    "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_State",
    "Domain_registeration_length", "Favicon", "port", "HTTPS_token", "Request_URL",
    "URL_of_Anchor", "Links_in_tags", "SFH", "Submitting_to_email", "Abnormal_URL",
    "Redirect", "on_mouseover", "RightClick", "popUpWidnow", "Iframe", "age_of_domain",
    "DNSRecord"
]


def _metrics(y_true, probabilities, predictions):
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, predictions, pos_label=1, average="binary", zero_division=0
    )
    tn, fp, fn, tp = confusion_matrix(y_true, predictions, labels=[0, 1]).ravel()
    return {
        "accuracy": round(float(accuracy_score(y_true, predictions)), 4),
        "phishing_precision": round(float(precision), 4),
        "phishing_recall": round(float(recall), 4),
        "phishing_f1": round(float(f1), 4),
        "roc_auc": round(float(roc_auc_score(y_true, probabilities)), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def _render_report(metadata: dict) -> str:
    m = metadata["test_metrics"]
    cm = m["confusion_matrix"]
    val_m = metadata["validation_metrics"]
    return f"""# Live 25-Feature URL Model Evaluation

## Overview

- **Schema Version**: `{metadata['schema_version']}`
- **Feature Count**: {metadata['expected_feature_count']} live-collectible features (dropped 5 uncollectible historical features)
- **Selected Estimator**: `{metadata['model_name']}`
- **Dataset**: UCI Phishing Websites (OpenML ID 4534)
- **Original Rows**: {metadata['dataset']['original_rows']}
- **Rows Evaluated After Deduplication**: {metadata['dataset']['rows_after_deduplication']}

## Live-Collectible Features (25)

{', '.join(metadata['feature_names'])}

## Validation Performance Comparison

| Model | Accuracy | Precision | Recall | F1 Score | ROC-AUC |
| --- | ---: | ---: | ---: | ---: | ---: |
| Random Forest | {val_m['random_forest']['accuracy']:.2%} | {val_m['random_forest']['phishing_precision']:.2%} | {val_m['random_forest']['phishing_recall']:.2%} | {val_m['random_forest']['phishing_f1']:.2%} | {val_m['random_forest']['roc_auc']:.2%} |
| Gradient Boosting | {val_m['gradient_boosting']['accuracy']:.2%} | {val_m['gradient_boosting']['phishing_precision']:.2%} | {val_m['gradient_boosting']['phishing_recall']:.2%} | {val_m['gradient_boosting']['phishing_f1']:.2%} | {val_m['gradient_boosting']['roc_auc']:.2%} |
| Logistic Regression | {val_m['logistic_regression']['accuracy']:.2%} | {val_m['logistic_regression']['phishing_precision']:.2%} | {val_m['logistic_regression']['phishing_recall']:.2%} | {val_m['logistic_regression']['phishing_f1']:.2%} | {val_m['logistic_regression']['roc_auc']:.2%} |

## Final Held-Out Test Metrics ({metadata['model_name']})

| Metric | Value |
| --- | ---: |
| Accuracy | {m['accuracy']:.2%} |
| Phishing Precision | {m['phishing_precision']:.2%} |
| Phishing Recall | {m['phishing_recall']:.2%} |
| Phishing F1 Score | {m['phishing_f1']:.2%} |
| ROC-AUC | {m['roc_auc']:.2%} |

### Confusion Matrix

| Actual / Predicted | Legitimate (0) | Phishing (1) |
| --- | ---: | ---: |
| Legitimate (0) | {cm['tn']} | {cm['fp']} |
| Phishing (1) | {cm['fn']} | {cm['tp']} |

True Positives: {cm['tp']}, True Negatives: {cm['tn']}, False Positives: {cm['fp']}, False Negatives: {cm['fn']}.
"""


def train_live_25_model(artifact_path: Path, report_path: Path) -> dict:
    print("Fetching UCI Phishing Websites dataset (OpenML 4534)...")
    bunch = fetch_openml(data_id=4534, as_frame=True)
    frame = bunch.frame.copy()

    # Convert all feature columns to int
    for col in LIVE_25_FEATURE_NAMES + ["Result"]:
        frame[col] = frame[col].astype(int)

    original_rows = len(frame)
    frame = frame.drop_duplicates().reset_index(drop=True)

    X = frame[LIVE_25_FEATURE_NAMES]
    y = (frame["Result"] == -1).astype(int)

    X_train_validation, X_test, y_train_validation, y_test = train_test_split(
        X, y, test_size=0.15, stratify=y, random_state=RANDOM_STATE
    )
    X_train, X_validation, y_train, y_validation = train_test_split(
        X_train_validation, y_train_validation, test_size=(0.15 / 0.85),
        stratify=y_train_validation, random_state=RANDOM_STATE
    )

    candidates = {
        "random_forest": RandomForestClassifier(
            n_estimators=300, min_samples_leaf=2, max_features="sqrt",
            n_jobs=-1, random_state=RANDOM_STATE, class_weight="balanced"
        ),
        "gradient_boosting": GradientBoostingClassifier(random_state=RANDOM_STATE),
        "logistic_regression": LogisticRegression(max_iter=2000, random_state=RANDOM_STATE),
    }

    validation_scores = {}
    for name, candidate in candidates.items():
        candidate.fit(X_train.to_numpy(), y_train)
        probabilities = candidate.predict_proba(X_validation.to_numpy())[:, 1]
        predictions = candidate.predict(X_validation.to_numpy())
        validation_scores[name] = _metrics(y_validation, probabilities, predictions)

    selected_name = max(
        validation_scores,
        key=lambda name: (validation_scores[name]["phishing_f1"], validation_scores[name]["phishing_recall"]),
    )

    model = candidates[selected_name]
    model.fit(X_train_validation.to_numpy(), y_train_validation)

    test_probabilities = model.predict_proba(X_test.to_numpy())[:, 1]
    test_predictions = model.predict(X_test.to_numpy())

    metadata = {
        "model_name": selected_name,
        "model_version": "2.1.0",
        "schema_version": FEATURE_SCHEMA_VERSION_25,
        "feature_names": LIVE_25_FEATURE_NAMES,
        "expected_feature_count": len(LIVE_25_FEATURE_NAMES),
        "label_mapping": {"-1": "phishing", "1": "legitimate"},
        "random_state": RANDOM_STATE,
        "trained_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset": {
            "identifier": "UCI Phishing Websites (OpenML ID 4534)",
            "original_rows": original_rows,
            "duplicate_rows_removed": original_rows - len(frame),
            "rows_after_deduplication": len(frame),
        },
        "validation_metrics": validation_scores,
        "test_metrics": _metrics(y_test, test_probabilities, test_predictions),
    }

    artifact = {
        "artifact_type": "phishshield_url_live_25_classifier",
        "schema_version": FEATURE_SCHEMA_VERSION_25,
        "feature_names": LIVE_25_FEATURE_NAMES,
        "metadata": metadata,
        "model": model,
    }

    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, artifact_path, compress=3)
    report_path.write_text(_render_report(metadata), encoding="utf-8")
    return metadata


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train 25-feature live URL model.")
    parser.add_argument("--artifact", type=Path, default=ARTIFACTS_DIR / "url_live_25_detector.joblib")
    parser.add_argument("--report", type=Path, default=Path("reports/model_evaluation_live_25.md"))
    args = parser.parse_args()
    meta = train_live_25_model(args.artifact, args.report)
    print(json.dumps(meta["test_metrics"], indent=2))
    print(f"Saved 25-feature live artifact: {args.artifact}")
    print(f"Saved 25-feature evaluation report: {args.report}")
