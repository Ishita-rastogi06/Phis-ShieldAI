from pathlib import Path

from feature_extractor import LIVE_25_FEATURE_NAMES


BASE_DIR = Path(__file__).resolve().parent
ARTIFACTS_DIR = BASE_DIR / "artifacts"
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
MODEL_TIMEOUT_SECONDS = 15

MODEL_REGISTRY = {
    "url_live_25_detector": {
        "filename": "url_live_25_detector.joblib",
        "display_name": "25-FEATURE LIVE RANDOM FOREST CLASSIFIER",
        "download_env": "URL_LIVE_25_MODEL_URL",
        "download_url": None,
        "schema_version": "uci-live-25-v1",
        "feature_names": LIVE_25_FEATURE_NAMES,
    },
    # Email artifacts are deliberately separate.  No synthetic model is used
    # when a legitimate, versioned email artifact has not been supplied.
    "email_detector": {
        "filename": "email_detector_v1.joblib",
        "display_name": "Email phishing classifier",
        "download_env": "EMAIL_MODEL_URL",
        "download_url": None,
    },
    "email_vectorizer": {
        "filename": "email_vectorizer_v1.joblib",
        "display_name": "Email vectorizer",
        "download_env": "EMAIL_VECTORIZER_URL",
        "download_url": None,
    },
}
