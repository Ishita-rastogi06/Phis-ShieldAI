"""Runtime inference for the versioned URL phishing model."""

from __future__ import annotations

from typing import Dict, Optional

from feature_extractor import FeatureUnavailableError, extract_live_features
from models.model_manager import load_model
from security.input_validation import validate_url


def predict_url(url: str) -> Dict[str, Optional[object]]:
    result: Dict[str, Optional[object]] = {
        "url": url,
        "prediction": None,
        "confidence": None,
        "model_available": False,
        "features": [],
        "error": None,
        "model_metadata": None,
    }
    if not validate_url(url):
        result["error"] = "Enter a valid URL with a hostname."
        return result
    try:
        features = extract_live_features(url)
    except (ValueError, FeatureUnavailableError) as error:
        result["error"] = "Live 25-Feature Model unavailable for this input: " + str(error)
        return result
    result["features"] = features

    artifact = load_model("url_live_25_detector")
    if artifact is None:
        result["error"] = (
            "The 25-feature live URL model artifact is unavailable. Add the bundled artifact; "
            "no prediction was generated."
        )
        return result
    try:
        model = artifact["model"]
        phishing_probability = float(model.predict_proba([features])[0][1])
        result.update({
            "prediction": int(phishing_probability >= 0.5),
            "confidence": round(phishing_probability * 100, 1),
            "model_available": True,
            "status": "AVAILABLE",
            "model_metadata": artifact["metadata"],
        })
    except (KeyError, TypeError, ValueError, IndexError, AttributeError) as error:
        result["error"] = f"The URL model could not score this input: {error}"
    return result
