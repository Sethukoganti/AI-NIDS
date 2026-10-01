#!/usr/bin/env python3
"""
Build per-class feature profiles from the cleaned CICIDS2017 training table.

These profiles are *evidence*: they let the explanation layer describe a flow
relative to how that attack family actually looks in the dataset, instead of
inventing characteristics.

    python ml/build_profiles.py

Output: backend/app/ml/class_profiles.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ml.cicids_config import (  # noqa: E402
    ARTIFACT_DIR,
    NORMAL_CLASS,
    PROCESSED_TABLE,
    TARGET_COLUMN,
    load_json,
)

BACKEND_ML_DIR = Path(__file__).resolve().parent.parent / "backend" / "app" / "ml"
TOP_N_FEATURES = 30


def main() -> None:
    if not PROCESSED_TABLE.exists():
        raise SystemExit(f"{PROCESSED_TABLE} not found - run build_dataset.py first")

    df = pd.read_parquet(PROCESSED_TABLE)
    importance_path = ARTIFACT_DIR / "feature_importance.json"
    if importance_path.exists():
        ranked = [i["feature"] for i in load_json(importance_path)["importances"]]
    else:  # fall back to variance ranking
        ranked = (
            df.drop(columns=[TARGET_COLUMN, "Label Code"], errors="ignore")
            .var(numeric_only=True)
            .sort_values(ascending=False)
            .index.tolist()
        )
    features = [f for f in ranked if f in df.columns][:TOP_N_FEATURES]

    profiles: dict[str, dict] = {}
    for cls, group in df.groupby(TARGET_COLUMN):
        subset = group[features].astype("float64")
        normal_subset = df[df[TARGET_COLUMN] == NORMAL_CLASS][features].astype("float64")
        entry = {"rows_in_training_table": int(len(group)), "features": {}}
        for feature in features:
            values = subset[feature].to_numpy()
            normal_values = normal_subset[feature].to_numpy()
            entry["features"][feature] = {
                "median": _f(np.median(values)),
                "mean": _f(np.mean(values)),
                "p95": _f(np.percentile(values, 95)),
                "max": _f(np.max(values)),
                "normal_median": _f(np.median(normal_values)),
                "ratio_vs_normal_median": _ratio(np.median(values), np.median(normal_values)),
            }
        profiles[str(cls)] = entry

    payload = {
        "source": "data/processed/cicids2017_subset.parquet (cleaned CICIDS2017 training table)",
        "note": (
            "Per-class medians of the most important model features. Used to describe how a "
            "flow compares with the traffic family it was assigned to and with normal traffic. "
            "These are dataset statistics, not per-prediction explanations."
        ),
        "features_ranked": features,
        "profiles": profiles,
    }
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    (ARTIFACT_DIR / "class_profiles.json").write_text(json.dumps(payload, indent=2))
    BACKEND_ML_DIR.mkdir(parents=True, exist_ok=True)
    (BACKEND_ML_DIR / "class_profiles.json").write_text(json.dumps(payload, indent=2))

    print(f"Profiles for {len(profiles)} classes x {len(features)} features written to:")
    print(f"  {ARTIFACT_DIR / 'class_profiles.json'}")
    print(f"  {BACKEND_ML_DIR / 'class_profiles.json'}")


def _f(value: float) -> float | None:
    value = float(value)
    return None if not np.isfinite(value) else round(value, 6)


def _ratio(a: float, b: float) -> float | None:
    a, b = float(a), float(b)
    if not np.isfinite(a) or not np.isfinite(b) or b == 0:
        return None
    return round(a / b, 6)


if __name__ == "__main__":
    main()
