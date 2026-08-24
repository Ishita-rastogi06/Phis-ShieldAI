"""Validated, cached access to versioned model artifacts."""

from __future__ import annotations

import hashlib
import os
import shutil
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

import joblib
import requests
from dotenv import load_dotenv

from .model_config import ARTIFACTS_DIR, MODEL_REGISTRY, MODEL_TIMEOUT_SECONDS

load_dotenv()


def get_model_path(model_key: str) -> Path:
    if model_key not in MODEL_REGISTRY:
        raise ValueError(f"Unknown model key: {model_key}")
    return ARTIFACTS_DIR / MODEL_REGISTRY[model_key]["filename"]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_artifact(model_key: str, artifact: Any) -> bool:
    if model_key == "url_live_25_detector":
        config = MODEL_REGISTRY[model_key]
        expected_cnt = 25
        return (
            isinstance(artifact, dict)
            and artifact.get("schema_version") == config["schema_version"]
            and artifact.get("feature_names") == config["feature_names"]
            and artifact.get("metadata", {}).get("expected_feature_count") == expected_cnt
            and getattr(artifact.get("model"), "n_features_in_", None) == expected_cnt
            and hasattr(artifact.get("model"), "predict")
            and hasattr(artifact.get("model"), "predict_proba")
        )
    return hasattr(artifact, "predict") or hasattr(artifact, "transform")


def _load_and_validate(model_key: str, path: Path) -> Optional[Any]:
    try:
        artifact = joblib.load(path)
    except (OSError, ValueError, TypeError, EOFError, KeyError, IndexError, ImportError, ModuleNotFoundError):
        return None
    return artifact if _validate_artifact(model_key, artifact) else None


def _download_model(url: str, destination: Path) -> Optional[Path]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    try:
        with requests.get(url, stream=True, timeout=MODEL_TIMEOUT_SECONDS) as response:
            response.raise_for_status()
            with temporary.open("wb") as output:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        output.write(chunk)
        shutil.move(str(temporary), destination)
        return destination
    except requests.RequestException:
        temporary.unlink(missing_ok=True)
        return None


def ensure_model(model_key: str) -> Optional[Path]:
    """Return a valid bundled/cached/downloaded artifact path, if available."""
    path = get_model_path(model_key)
    if path.exists():
        if _load_and_validate(model_key, path) is not None:
            return path
        path.unlink(missing_ok=True)

    env_name = MODEL_REGISTRY[model_key].get("download_env")
    download_url = os.getenv(env_name or "") or MODEL_REGISTRY[model_key].get("download_url")
    if not download_url:
        return None

    downloaded = _download_model(download_url, path)
    if downloaded is None or _load_and_validate(model_key, downloaded) is None:
        path.unlink(missing_ok=True)
        return None
    return downloaded


@lru_cache(maxsize=None)
def load_model(model_key: str) -> Optional[Any]:
    path = ensure_model(model_key)
    return _load_and_validate(model_key, path) if path is not None else None


def is_model_available(model_key: str) -> bool:
    return ensure_model(model_key) is not None


def model_checksum(model_key: str) -> Optional[str]:
    path = ensure_model(model_key)
    return _sha256(path) if path is not None else None
