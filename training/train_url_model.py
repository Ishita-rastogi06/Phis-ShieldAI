"""Train the production URL classifier from the recovered UCI-format dataset.

This maintainer-only command never runs during application startup.  The
runtime artifact contains the fitted estimator and the exact input schema.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support, roc_auc_score
from sklearn.model_selection import train_test_split

from feature_extractor import FEATURE_SCHEMA_VERSION, URL_FEATURE_NAMES
from models.model_config import ARTIFACTS_DIR

RANDOM_STATE = 42
TARGET_COLUMN = "Result"


def _checksum(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
    return f"""# URL model evaluation

## Dataset

- Source: recovered `dataset.csv` (UCI Phishing Websites schema)
- Original rows: {metadata['dataset']['original_rows']}
- Exact duplicate rows removed before splitting: {metadata['dataset']['duplicate_rows_removed']}
- Rows evaluated after deduplication: {metadata['dataset']['rows_after_deduplication']}
- Label mapping: `Result=-1` is phishing (`1`); `Result=1` is legitimate (`0`).
- Dataset checksum (SHA-256): `{metadata['dataset']['sha256']}`

## Model and preprocessing

The artifact uses the validation-selected `{metadata['model_name']}` classifier
and all 30 UCI features, in this exact order:
`{', '.join(metadata['feature_names'])}`.

At inference, URL, webpage, DNS/WHOIS, and configured external-intelligence
providers collect this same schema. If any required source is unavailable,
inference fails clearly rather than filling a feature with a made-up value.

## Split strategy

Duplicate rows were removed before a stratified 70%/15%/15% train/validation/test
split. The validation set selected the estimator; the test set below was held out
until final evaluation. Random seed: {metadata['random_state']}.

## Held-out test metrics

| Metric | Value |
| --- | ---: |
| Accuracy | {m['accuracy']:.2%} |
| Phishing precision | {m['phishing_precision']:.2%} |
| Phishing recall | {m['phishing_recall']:.2%} |
| Phishing F1 | {m['phishing_f1']:.2%} |
| ROC-AUC | {m['roc_auc']:.2%} |

### Confusion matrix

| Actual / predicted | Legitimate | Phishing |
| --- | ---: | ---: |
| Legitimate | {cm['tn']} | {cm['fp']} |
| Phishing | {cm['fn']} | {cm['tp']} |

False negatives: {cm['fn']}; false positives: {cm['fp']}.

## Limitations

This is a historical, feature-engineered benchmark. Its performance does not
guarantee protection from new phishing campaigns. The model is one signal; the
application also presents separate brand and threat-intelligence signals.
"""


def train(dataset_path: Path, artifact_path: Path, report_path: Path) -> dict:
    frame = pd.read_csv(dataset_path)
    if TARGET_COLUMN not in frame.columns or any(name not in frame.columns for name in URL_FEATURE_NAMES):
        raise ValueError(
            "Dataset is missing one or more required URL-only UCI columns. "
            f"Required: {URL_FEATURE_NAMES + [TARGET_COLUMN]}; got {frame.columns.tolist()}."
        )
    if frame.isna().any().any():
        raise ValueError("Training dataset contains missing values.")
    if not frame.apply(lambda col: pd.api.types.is_integer_dtype(col)).all():
        raise ValueError("Training dataset must contain integer-coded features.")
    if not set(frame[TARGET_COLUMN]).issubset({-1, 1}):
        raise ValueError("Result labels must be -1 (phishing) or 1 (legitimate).")

    original_rows = len(frame)
    frame = frame.drop_duplicates().reset_index(drop=True)
    X = frame[URL_FEATURE_NAMES]
    y = (frame[TARGET_COLUMN] == -1).astype(int)

    X_train_validation, X_test, y_train_validation, y_test = train_test_split(
        X, y, test_size=0.15, stratify=y, random_state=RANDOM_STATE
    )
    X_train, X_validation, y_train, y_validation = train_test_split(
        X_train_validation, y_train_validation, test_size=(0.15 / 0.85),
        stratify=y_train_validation, random_state=RANDOM_STATE
    )
    candidates = {
        "logistic_regression": LogisticRegression(max_iter=2000, random_state=RANDOM_STATE),
        "gradient_boosting": GradientBoostingClassifier(random_state=RANDOM_STATE),
        "random_forest": RandomForestClassifier(
            n_estimators=300, min_samples_leaf=2, max_features="sqrt",
            n_jobs=1, random_state=RANDOM_STATE, class_weight="balanced",
        ),
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
        "model_version": "2.0.0",
        "schema_version": FEATURE_SCHEMA_VERSION,
        "feature_names": URL_FEATURE_NAMES,
        "expected_feature_count": len(URL_FEATURE_NAMES),
        "label_mapping": {"-1": "phishing", "1": "legitimate"},
        "random_state": RANDOM_STATE,
        "trained_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset": {
            "identifier": dataset_path.name,
            "sha256": _checksum(dataset_path),
            "original_rows": original_rows,
            "duplicate_rows_removed": original_rows - len(frame),
            "rows_after_deduplication": len(frame),
        },
        "validation_metrics": validation_scores,
        "test_metrics": _metrics(y_test, test_probabilities, test_predictions),
    }
    artifact = {
        "artifact_type": "phishshield_url_classifier",
        "schema_version": FEATURE_SCHEMA_VERSION,
        "feature_names": URL_FEATURE_NAMES,
        "metadata": metadata,
        "model": model,
    }
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(artifact, artifact_path, compress=3)
    report_path.write_text(_render_report(metadata), encoding="utf-8")
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the PhishShield URL model.")
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument("--artifact", type=Path, default=ARTIFACTS_DIR / "url_lexical_detector.joblib")
    parser.add_argument("--report", type=Path, default=Path("reports/model_evaluation.md"))
    args = parser.parse_args()
    metadata = train(args.dataset, args.artifact, args.report)
    print(json.dumps(metadata["test_metrics"], indent=2))
    print(f"Saved artifact: {args.artifact}")
    print(f"Saved evaluation: {args.report}")


if __name__ == "__main__":
    main()
