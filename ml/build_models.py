"""Deprecated compatibility entry point.

Runtime model generation is intentionally disabled.  Use
``python -m training.train_url_model --dataset <path>`` during maintainer-only
retraining and commit the validated small URL artifact or publish it as a
versioned release asset.
"""


def build_and_save_models() -> None:
    raise RuntimeError(
        "Runtime model generation is disabled. Train models only through the "
        "maintainer training pipeline."
    )


if __name__ == "__main__":
    raise SystemExit("Use: python -m training.train_url_model --dataset <dataset.csv>")
