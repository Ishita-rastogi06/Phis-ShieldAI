from pathlib import Path

from feature_extractor import FEATURE_SCHEMA_VERSION, URL_FEATURE_NAMES


BASE_DIR = Path(__file__).resolve().parent
ARTIFACTS_DIR = BASE_DIR / "artifacts"
ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
MODEL_TIMEOUT_SECONDS = 15

MODEL_REGISTRY = {
    "url_detector": {
        "filename": "url_lexical_detector.joblib",
        "display_name": "LEGACY UCI 30-FEATURE MODEL",
        "download_env": "URL_MODEL_URL",
        "download_url": None,
        "schema_version": FEATURE_SCHEMA_VERSION,
        "feature_names": URL_FEATURE_NAMES,
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
