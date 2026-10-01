#!/usr/bin/env python3
"""
AI-NIDS - Random Forest training + held-out evaluation + artifact export.

Reads the cleaned CICIDS2017 table produced by ``build_dataset.py``, trains the
production Random Forest classifier, evaluates it on the held-out test split and
writes every artifact the backend needs into ``backend/app/ml/``.

  * Algorithm        : RandomForestClassifier  (primary / production model)
  * n_estimators     : 100
  * random_state     : 42
  * split            : 70 / 30 stratified, random_state = 42

Usage
-----
    python ml/train_model.py
    python ml/train_model.py --max-depth 24 --trees 100
"""

from __future__ import annotations

import argparse
import json
import platform
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ml.cicids_config import (  # noqa: E402
    ARTIFACT_DIR,
    LABEL_TO_ATTACK_TYPE,
    DATASET_STATS,
    MAX_ONEHOT_LEVELS,
    MIN_FEATURE_COVERAGE,
    MIN_SAMPLES_LEAF,
    N_ESTIMATORS,
    NORMAL_CLASS,
    PROCESSED_TABLE,
    RANDOM_STATE,
    RISK_RULES,
    SOURCE_LABEL_COLUMN,
    TARGET_COLUMN,
    TEST_SIZE,
    load_json,
)

BACKEND_ML_DIR = Path(__file__).resolve().parent.parent / "backend" / "app" / "ml"
LABEL_CODE_COLUMN = "Label Code"
LABEL_CODES_FILE = Path(__file__).resolve().parent.parent / "data" / "processed" / "label_codes.json"
FRONTEND_SAMPLES = Path(__file__).resolve().parent.parent / "frontend" / "public" / "samples"


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def human_mb(path: Path) -> float:
    return round(path.stat().st_size / 1e6, 2)


def export_demo_samples(df_test: pd.DataFrame, features: list[str]) -> dict:
    """Write held-out test rows as demo CSVs (never used for training)."""
    rng = np.random.default_rng(RANDOM_STATE)
    normal = df_test[df_test[TARGET_COLUMN] == NORMAL_CLASS]
    attacks = df_test[df_test[TARGET_COLUMN] != NORMAL_CLASS]

    n_normal, n_attack = 900, 600
    picked = [
        normal.sample(n=min(n_normal, len(normal)), random_state=RANDOM_STATE),
        attacks.sample(n=min(n_attack, len(attacks)), random_state=RANDOM_STATE),
    ]
    sample = pd.concat(picked).sample(frac=1.0, random_state=RANDOM_STATE).reset_index(drop=True)
    # rebuild the human-readable raw CICIDS2017 Label from its integer code
    code_to_label = load_json(LABEL_CODES_FILE)["code_to_label"]
    sample[SOURCE_LABEL_COLUMN] = sample[LABEL_CODE_COLUMN].map(
        lambda c: code_to_label.get(str(int(c)), "UNKNOWN")
    )
    sample = sample[features + [SOURCE_LABEL_COLUMN]]

    FRONTEND_SAMPLES.mkdir(parents=True, exist_ok=True)
    main_csv = FRONTEND_SAMPLES / "sample_traffic.csv"
    sample.to_csv(main_csv, index=False)

    # A shuffled "stream" for the live-simulation page: 800 records, mostly
    # benign with attack bursts, in a stable pseudo-random order.
    stream = sample.sample(n=min(800, len(sample)), random_state=7).reset_index(drop=True)
    stream_csv = FRONTEND_SAMPLES / "simulation_stream.csv"
    stream.to_csv(stream_csv, index=False)

    meta = {
        "sample_traffic": {
            "file": main_csv.name,
            "rows": int(len(sample)),
            "columns": int(sample.shape[1]),
            "bytes": main_csv.stat().st_size,
            "normal_rows": int((sample[SOURCE_LABEL_COLUMN] == "BENIGN").sum()),
            "attack_rows": int((sample[SOURCE_LABEL_COLUMN] != "BENIGN").sum()),
            "source": "held-out 30% test split (never seen during training)",
        },
        "simulation_stream": {
            "file": stream_csv.name,
            "rows": int(len(stream)),
            "columns": int(stream.shape[1]),
            "bytes": stream_csv.stat().st_size,
            "source": "held-out 30% test split, shuffled",
        },
    }
    return meta


def main() -> None:
    ap = argparse.ArgumentParser(description="Train the AI-NIDS Random Forest model")
    ap.add_argument("--trees", type=int, default=N_ESTIMATORS)
    ap.add_argument("--max-depth", type=int, default=None)
    ap.add_argument("--min-samples-leaf", type=int, default=MIN_SAMPLES_LEAF)
    ap.add_argument("--no-size-guard", action="store_true", help="use scikit-learn defaults (min_samples_leaf=1)")
    ap.add_argument("--test-size", type=float, default=TEST_SIZE)
    args = ap.parse_args()

    min_leaf = 1 if args.no_size_guard else args.min_samples_leaf

    if not PROCESSED_TABLE.exists():
        raise SystemExit(
            f"{PROCESSED_TABLE} not found.\nRun:  python ml/build_dataset.py --download"
        )

    print("=" * 72)
    print("AI-NIDS  ::  Random Forest training")
    print("=" * 72)
    df = pd.read_parquet(PROCESSED_TABLE)
    features = [c for c in df.columns if c not in (TARGET_COLUMN, SOURCE_LABEL_COLUMN, LABEL_CODE_COLUMN)]
    print(f"Training table : {df.shape[0]:,} rows x {len(features)} features")
    print(f"Classes        : {df[TARGET_COLUMN].nunique()}")

    X = df[features].astype("float32")
    y = df[TARGET_COLUMN]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=RANDOM_STATE, stratify=y
    )
    print(f"Train / test   : {len(X_train):,} / {len(X_test):,}  "
          f"({100*(1-args.test_size):.0f}% / {100*args.test_size:.0f}%)")

    clf = RandomForestClassifier(
        n_estimators=args.trees,
        random_state=RANDOM_STATE,
        n_jobs=-1,
        min_samples_leaf=min_leaf,
        max_depth=args.max_depth,
    )
    print(f"\nFitting RandomForestClassifier(n_estimators={args.trees}, "
          f"min_samples_leaf={min_leaf}, max_depth={args.max_depth}, "
          f"random_state={RANDOM_STATE}, n_jobs=-1) ...")
    t0 = time.time()
    clf.fit(X_train, y_train)
    fit_seconds = time.time() - t0
    print(f"Fit finished in {fit_seconds:.1f}s")

    t0 = time.time()
    y_pred = clf.predict(X_test)
    predict_seconds = time.time() - t0

    accuracy = float(accuracy_score(y_test, y_pred))
    labels = sorted(y.unique())
    report = classification_report(y_test, y_pred, output_dict=True, zero_division=0)
    cm = confusion_matrix(y_test, y_pred, labels=labels)
    macro_f1 = float(f1_score(y_test, y_pred, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))

    print(f"\nTest accuracy  : {accuracy:.10f}")
    print(f"Macro F1       : {macro_f1:.6f}")
    print(f"Weighted F1    : {weighted_f1:.6f}")
    print(f"Predict time   : {predict_seconds:.1f}s for {len(X_test):,} rows "
          f"({predict_seconds/max(len(X_test),1)*1e6:.0f} us/row)")
    print("\nPer-class report")
    print(f"{'class':20s} {'precision':>10s} {'recall':>10s} {'f1':>10s} {'support':>10s}")
    for cls in labels:
        row = report[cls]
        print(f"{cls:20s} {row['precision']:10.4f} {row['recall']:10.4f} {row['f1-score']:10.4f} {row['support']:10.0f}")

    print("\nConfusion matrix (rows = actual, cols = predicted)")
    header = "".join(f"{c[:11]:>13s}" for c in labels)
    print(f"{'':20s}{header}")
    for name, row in zip(labels, cm):
        print(f"{name:20s}" + "".join(f"{v:13,d}" for v in row))

    # ---------------------------------------------------------------- artifacts
    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    BACKEND_ML_DIR.mkdir(parents=True, exist_ok=True)

    model_path = ARTIFACT_DIR / "random_forest_model.joblib"
    joblib.dump(clf, model_path, compress=3)
    model_size_mb = human_mb(model_path)
    print(f"\nSerialized model: {model_path.name}  ({model_size_mb} MB)")

    feature_columns = {
        "schema_version": "1.0",
        "target_column": TARGET_COLUMN,
        "source_label_column": SOURCE_LABEL_COLUMN,
        "n_features": len(features),
        "feature_columns": features,
        "dropped_columns": load_json(DATASET_STATS).get("dropped_constant_columns", []),
        "min_feature_coverage": MIN_FEATURE_COVERAGE,
        "max_onehot_levels": MAX_ONEHOT_LEVELS,
        "note": (
            "Column order in 'feature_columns' is the exact order the model was "
            "trained with. The inference pipeline must not reorder these columns."
        ),
    }
    (ARTIFACT_DIR / "feature_columns.json").write_text(json.dumps(feature_columns, indent=2))

    class_index = {cls: i for i, cls in enumerate(clf.classes_.tolist())}
    label_mapping = {
        "class_index": class_index,
        "index_to_class": {str(v): k for k, v in class_index.items()},
        "normal_class": NORMAL_CLASS,
        "detailed_label_to_category": dict(LABEL_TO_ATTACK_TYPE),
    }
    (ARTIFACT_DIR / "label_mapping.json").write_text(json.dumps(label_mapping, indent=2))

    # Median of every feature on the *training* split. Used only to impute
    # expected-but-absent columns at inference, and always reported back to the
    # caller in the API response as an explicit limitation.
    medians = X_train.median(numeric_only=True)
    medians = {k: float(v) if np.isfinite(v) else 0.0 for k, v in medians.items()}
    preprocessing_config = {
        "schema_version": "1.0",
        "numeric_only": True,
        "steps": [
            "canonicalise column headers (strip whitespace/BOM)",
            "map source 'Label' column to 'Attack Type' when present (ground-truth only)",
            "coerce features to numeric",
            "replace +inf/-inf with NaN",
            "drop rows containing NaN (training-time policy)",
            "drop exact duplicate flow records (training-time policy)",
            "drop constant / non-informative columns",
            "reorder to the exact training feature order",
        ],
        "inference_missing_feature_policy": (
            "features expected but absent from the uploaded file are filled with the "
            "training-split median and reported in 'imputed_features'"
        ),
        "feature_medians": medians,
        "training_only_steps": ["drop rows containing NaN", "drop exact duplicate flow records"],
        "deduplicate_at_inference": False,
        "one_hot": {
            "enabled": True,
            "applies_to": "non-numeric feature columns present after canonicalisation",
            "max_levels": MAX_ONEHOT_LEVELS,
            "note": "CICIDS2017 MachineLearningCVE is fully numeric; one-hot is a guard for other flow exports.",
        },
    }
    (ARTIFACT_DIR / "preprocessing_config.json").write_text(json.dumps(preprocessing_config, indent=2))

    importances = sorted(
        ({"feature": f, "importance": float(v)} for f, v in zip(features, clf.feature_importances_)),
        key=lambda d: -d["importance"],
    )
    (ARTIFACT_DIR / "feature_importance.json").write_text(
        json.dumps(
            {
                "source": "sklearn RandomForestClassifier.feature_importances_",
                "method": "mean decrease in impurity (Gini) over all decision trees",
                "totals": {
                    "n_features": len(importances),
                    "sum": float(sum(i["importance"] for i in importances)),
                },
                "importances": importances,
            },
            indent=2,
        )
    )

    evaluation = {
        "evaluated_at": utcnow(),
        "split": {"train_fraction": 1 - args.test_size, "test_fraction": args.test_size, "random_state": RANDOM_STATE},
        "n_train": int(len(X_train)),
        "n_test": int(len(X_test)),
        "accuracy": accuracy,
        "macro_f1": macro_f1,
        "weighted_f1": weighted_f1,
        "per_class": {
            cls: {
                "precision": report[cls]["precision"],
                "recall": report[cls]["recall"],
                "f1": report[cls]["f1-score"],
                "support": int(report[cls]["support"]),
            }
            for cls in labels
        },
        "confusion_matrix": {"labels": labels, "matrix": cm.tolist()},
        "timing": {
            "fit_seconds": round(fit_seconds, 2),
            "predict_seconds": round(predict_seconds, 2),
            "predict_us_per_row": round(predict_seconds / max(len(X_test), 1) * 1e6, 2),
        },
        "disclaimer": (
            "Accuracy is measured on the held-out 30% split of the cleaned CICIDS2017 "
            "table described in model_metadata.json. It is NOT a guarantee of "
            "real-world detection performance: the dataset is a 2017 lab capture, the "
            "training table is a stratified subsample, and no live-network validation "
            "has been performed."
        ),
    }
    (ARTIFACT_DIR / "evaluation.json").write_text(json.dumps(evaluation, indent=2))

    stats = load_json(DATASET_STATS)
    metadata = {
        "name": "AI-NIDS Random Forest Intrusion Detector",
        "version": "1.0.0",
        "algorithm": "Random Forest",
        "algorithm_detail": "sklearn.ensemble.RandomForestClassifier",
        "n_estimators": args.trees,
        "random_state": RANDOM_STATE,
        "n_jobs": -1,
        "min_samples_leaf": min_leaf,
        "max_depth": args.max_depth,
        "dataset": "CICIDS2017",
        "dataset_detail": "MachineLearningCVE flow features (ISCX / Canadian Institute for Cybersecurity)",
        "dataset_files": list(stats.get("source_files", {}).keys()),
        "full_dataset": {
            "rows": stats.get("full_dataset_rows"),
            "columns": stats.get("full_dataset_columns"),
            "class_counts": stats.get("class_counts_full_dataset"),
        },
        "training_table": {
            "rows": int(len(df)),
            "features": len(features),
            "class_counts": stats.get("class_counts_training_table"),
            "sampling": stats.get("sampling"),
        },
        "train_split": round(1 - args.test_size, 2),
        "test_split": round(args.test_size, 2),
        "classes": labels,
        "n_classes": len(labels),
        "normal_class": NORMAL_CLASS,
        "attack_classes": [c for c in labels if c != NORMAL_CLASS],
        "model_file": "random_forest_model.joblib",
        "model_size_mb": model_size_mb,
        "serialization": "joblib (compressed)",
        "feature_file": "feature_columns.json",
        "n_features": len(features),
        "risk_rules": RISK_RULES,
        "environment": {
            "python": platform.python_version(),
            "scikit_learn": sklearn.__version__,
            "pandas": pd.__version__,
            "numpy": np.__version__,
        },
        "trained_at": utcnow(),
        "limitations": [
            "Trained on a 2017 research-lab capture; traffic from 2018+ is out of distribution.",
            "Only the 10 CICIDS2017 attack families above can be recognised; anything else is "
            "either mapped to a known family or reported as normal traffic.",
            "Labels in CICIDS2017 are derived from the attack schedule, which is known to contain "
            "some noise (published label-noise analyses put usable accuracy well below 100%).",
            "Accuracy is reported on the held-out test split of a stratified subsample, not on a "
            "fresh live network.",
        ],
    }
    (ARTIFACT_DIR / "model_metadata.json").write_text(json.dumps(metadata, indent=2))

    samples = export_demo_samples(df.loc[X_test.index], features)
    metadata["demo_samples"] = samples

    # ---- publish the registry into the backend ------------------------------ #
    shutil.copy2(LABEL_CODES_FILE, ARTIFACT_DIR / "label_codes.json")
    for fname in [
        "random_forest_model.joblib",
        "label_codes.json",
        "feature_columns.json",
        "label_mapping.json",
        "preprocessing_config.json",
        "model_metadata.json",
        "evaluation.json",
        "feature_importance.json",
    ]:
        shutil.copy2(ARTIFACT_DIR / fname, BACKEND_ML_DIR / fname)
    (BACKEND_ML_DIR / "model_metadata.json").write_text(json.dumps(metadata, indent=2))
    (ARTIFACT_DIR / "model_metadata.json").write_text(json.dumps(metadata, indent=2))
    shutil.copy2(DATASET_STATS, ARTIFACT_DIR / "dataset_stats.json")

    print(f"\nArtifacts written to {ARTIFACT_DIR} and {BACKEND_ML_DIR}")
    print(f"Demo CSV exported : {FRONTEND_SAMPLES / 'sample_traffic.csv'} "
          f"({samples['sample_traffic']['rows']} held-out rows)")
    print("=" * 72)
    print("Model ready.  Start the backend with:  uvicorn app.main:app --app-dir backend")


if __name__ == "__main__":
    main()
