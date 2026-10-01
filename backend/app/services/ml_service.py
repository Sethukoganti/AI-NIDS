"""
Machine-learning service - the single owner of the trained Random Forest.

The model is loaded **once** at application startup from
``random_forest_model.joblib`` (never retrained on the fly) together with its
feature schema, label mapping and metadata.

Provided capabilities
---------------------
* ``predict``        - class labels + calibrated-ish probabilities (predict_proba)
* ``explain_shap``   - per-record TreeSHAP contributions for the predicted class
* ``importance``     - global ``feature_importances_`` (mean decrease in impurity)
* ``deviations``     - fast per-record heuristic ranking (documented as such)
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("ainids.ml")


class ModelUnavailableError(Exception):
    """Raised when the trained model cannot serve a request."""


def _read_json(path: str | Path, default: Any = None) -> Any:
    p = Path(path)
    if not p.exists():
        return default
    with open(p, "r", encoding="utf-8") as fh:
        return json.load(fh)


class ModelService:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.model = None
        self.feature_columns: dict = {}
        self.metadata: dict = {}
        self.evaluation: dict = {}
        self.feature_importance: dict = {}
        self.preprocessing_config: dict = {}
        self.label_mapping: dict = {}
        self.label_codes: dict = {}
        self.reference_stats: dict = {}
        self.class_profiles: dict = {}
        self._explainer = None
        self._explainer_error: str | None = None
        self.loaded_at: float | None = None
        self.load_seconds: float | None = None
        self.load_error: str | None = None

    # ------------------------------------------------------------------ load
    @property
    def is_loaded(self) -> bool:
        return self.model is not None

    def load(self) -> None:
        with self._lock:
            t0 = time.time()
            try:
                import joblib

                model_path = Path(settings.MODEL_PATH)
                if not model_path.exists():
                    raise FileNotFoundError(f"model artifact not found: {model_path}")

                self.model = joblib.load(model_path)
                self.feature_columns = _read_json(settings.FEATURE_COLUMNS_PATH, {}) or {}
                self.metadata = _read_json(settings.MODEL_METADATA_PATH, {}) or {}
                self.evaluation = _read_json(settings.EVALUATION_PATH, {}) or {}
                self.feature_importance = _read_json(settings.FEATURE_IMPORTANCE_PATH, {}) or {}
                self.preprocessing_config = _read_json(settings.PREPROCESSING_CONFIG_PATH, {}) or {}
                self.label_mapping = _read_json(settings.LABEL_MAPPING_PATH, {}) or {}
                self.reference_stats = _read_json(settings.DATASET_STATS_PATH, {}) or {}
                profile_path = Path(settings.DATASET_STATS_PATH).parent / "class_profiles.json"
                self.class_profiles = _read_json(profile_path, {}) or {}

                expected = list(self.feature_columns.get("feature_columns", []))
                raw_names = getattr(self.model, "feature_names_in_", None)
                actual = [str(n) for n in raw_names] if raw_names is not None else []
                if expected and actual and expected != actual:
                    raise ValueError(
                        "feature schema mismatch: feature_columns.json does not match the "
                        "feature order the model was trained with"
                    )
                if self.model is not None and hasattr(self.model, "n_features_in_"):
                    if expected and int(self.model.n_features_in_) != len(expected):
                        raise ValueError(
                            f"model expects {self.model.n_features_in_} features but the schema "
                            f"declares {len(expected)}"
                        )
                if not hasattr(self.model, "predict_proba"):
                    raise ValueError("loaded estimator does not expose predict_proba")

                self.load_error = None
                self.loaded_at = time.time()
                self.load_seconds = round(self.loaded_at - t0, 3)
                logger.info(
                    "model loaded: %s classes=%s features=%d in %.2fs",
                    self.metadata.get("algorithm", type(self.model).__name__),
                    len(self.model.classes_) if hasattr(self.model, "classes_") else "?",
                    len(expected) or getattr(self.model, "n_features_in_", 0),
                    self.load_seconds,
                )
            except Exception as exc:  # keep the API alive, report via /api/health
                self.model = None
                self.load_error = f"{type(exc).__name__}: {exc}"
                logger.error("MODEL LOAD FAILED: %s", self.load_error)

    def require_model(self):
        if not self.is_loaded:
            raise ModelUnavailableError(
                "ML model is currently unavailable." + (f" ({self.load_error})" if self.load_error else "")
            )
        return self.model

    # --------------------------------------------------------------- predict
    @property
    def classes_(self) -> list[str]:
        self.require_model()
        return list(self.model.classes_)

    @property
    def normal_class(self) -> str:
        return self.metadata.get("normal_class", "Normal Traffic")

    def feature_names(self) -> list[str]:
        names = list(self.feature_columns.get("feature_columns", []))
        if names:
            return names
        return list(getattr(self.model, "feature_names_in_", []) or [])

    def predict(self, features: pd.DataFrame, batch_size: int = 20_000) -> dict:
        """
        Run inference on an aligned feature matrix.

        Returns labels, confidences, the full probability matrix and per-class
        probabilities for each row.
        """
        model = self.require_model()
        expected = self.feature_names()
        if list(features.columns) != expected:
            raise ValueError(
                "feature order mismatch: the prepared matrix does not match the trained "
                "feature order (refusing to predict)"
            )

        n = len(features)
        labels: list[str] = []
        confidences: list[float] = []
        proba_rows: list[np.ndarray] = []

        for start in range(0, n, batch_size):
            chunk = features.iloc[start : start + batch_size]
            # pass the DataFrame so scikit-learn sees the trained feature names
            proba = model.predict_proba(chunk)
            idx = np.argmax(proba, axis=1)
            labels.extend(model.classes_[idx].tolist())
            confidences.extend(proba[np.arange(len(chunk)), idx].tolist())
            proba_rows.append(proba.astype("float32"))

        probability_matrix = np.vstack(proba_rows) if proba_rows else np.zeros((0, len(self.classes_)))
        return {
            "labels": labels,
            "confidences": np.asarray(confidences, dtype="float64"),
            "probabilities": probability_matrix,
            "classes": self.classes_,
        }

    # ------------------------------------------------------------- importance
    def importance(self, top: int | None = None) -> dict:
        values = self.feature_importance.get("importances")
        if not values and self.is_loaded:
            self.require_model()
            values = sorted(
                (
                    {"feature": f, "importance": float(v)}
                    for f, v in zip(self.feature_names(), self.model.feature_importances_)
                ),
                key=lambda d: -d["importance"],
            )
        values = values or []
        return {
            "method": self.feature_importance.get(
                "method", "mean decrease in impurity (Gini) over all decision trees"
            ),
            "source": self.feature_importance.get("source", "sklearn feature_importances_"),
            "total_features": len(values),
            "importances": values[:top] if top else values,
        }

    # ------------------------------------------------------------------- shap
    def _get_explainer(self):
        if self._explainer is not None:
            return self._explainer
        if self._explainer_error:
            raise ModelUnavailableError(f"SHAP explainer unavailable: {self._explainer_error}")
        model = self.require_model()
        try:
            import shap

            self._explainer = shap.TreeExplainer(model, feature_perturbation="tree_path_dependent")
            logger.info("SHAP TreeExplainer initialised for %s", type(model).__name__)
        except Exception as exc:
            self._explainer_error = f"{type(exc).__name__}: {exc}"
            logger.warning("SHAP unavailable, falling back to feature importance: %s", self._explainer_error)
            raise ModelUnavailableError(f"SHAP explainer unavailable: {self._explainer_error}") from exc
        return self._explainer

    def explain_shap(self, features: pd.DataFrame, class_name: str, max_rows: int = 1) -> dict:
        """
        Real per-record TreeSHAP contributions for the requested class.

        Returns ``contributions`` = [{feature, value, shap_value, impact_pct}].
        Raises ``ModelUnavailableError`` when SHAP cannot run - callers must then
        fall back to global feature importance and label it as such.
        """
        explainer = self._get_explainer()
        subset = features.iloc[:max_rows]
        values = explainer.shap_values(subset.to_numpy(dtype="float32"), check_additivity=False)

        classes = self.classes_
        class_idx = classes.index(class_name) if class_name in classes else int(
            np.argmax(self.predict(subset)["probabilities"][0])
        )
        # shap returns either a list (one array per class) or a 3-D array
        if isinstance(values, list):
            sv = np.asarray(values[class_idx])
        else:
            arr = np.asarray(values)
            if arr.ndim == 3:
                sv = arr[:, :, class_idx] if arr.shape[2] == len(classes) else arr[class_idx]
            else:
                sv = arr
        row = sv[0] if sv.ndim > 1 else sv

        names = self.feature_names()
        base_value = explainer.expected_value
        if isinstance(base_value, (list, np.ndarray)):
            base = float(np.asarray(base_value).ravel()[class_idx])
        else:
            base = float(base_value)

        contributions = [
            {
                "feature": name,
                "value": float(subset.iloc[0][name]),
                "shap_value": float(value),
                "direction": "attack" if value > 0 else "normal",
            }
            for name, value in zip(names, row)
        ]
        total = sum(abs(c["shap_value"]) for c in contributions) or 1.0
        for c in contributions:
            c["impact_pct"] = round(100 * abs(c["shap_value"]) / total, 2)
        contributions.sort(key=lambda c: -abs(c["shap_value"]))

        return {
            "method": "tree_shap",
            "method_label": "TreeSHAP (per-record SHAP values)",
            "explained_class": class_name,
            "base_value": round(base, 6),
            "predicted_value": round(base + float(np.sum(row)), 6),
            "contributions": contributions,
        }

    def deviations(self, features: pd.DataFrame, top: int = 6) -> list[dict]:
        """
        Fast, documented *heuristic* explanation used when storing a prediction:
        global importance weighted by how far each feature sits from the training
        median. It is NOT a per-prediction attribution - the API labels it as a
        heuristic and ``/explain`` returns real TreeSHAP values.
        """
        medians = self.preprocessing_config.get("feature_medians", {})
        importances = {i["feature"]: i["importance"] for i in self.importance()["importances"]}
        names = self.feature_names()

        rows = []
        values = features.to_numpy(dtype="float64")
        for r in range(values.shape[0]):
            scored = []
            for j, name in enumerate(names):
                imp = importances.get(name, 0.0)
                median = float(medians.get(name, 0.0))
                value = float(values[r, j])
                spread = abs(value - median)
                # normalise by magnitude so huge counters do not dominate blindly
                scale = max(abs(median), 1.0)
                scored.append(
                    {
                        "feature": name,
                        "value": value,
                        "importance": round(imp, 6),
                        "deviation_from_median": round(spread, 6),
                        "score": round(imp * min(spread / scale, 1e3), 8),
                    }
                )
            scored.sort(key=lambda d: -d["score"])
            rows.append(scored[:top])
        return rows

    # --------------------------------------------------------------- summary
    def info(self) -> dict:
        meta = dict(self.metadata)
        meta.update(
            {
                "loaded": self.is_loaded,
                "load_error": self.load_error,
                "loaded_at": self.loaded_at,
                "load_seconds": self.load_seconds,
                "n_features": len(self.feature_names()),
                "classes": self.classes_ if self.is_loaded else meta.get("classes", []),
                "normal_class": self.normal_class,
                "evaluation": {
                    "accuracy": self.evaluation.get("accuracy"),
                    "macro_f1": self.evaluation.get("macro_f1"),
                    "weighted_f1": self.evaluation.get("weighted_f1"),
                    "n_test": self.evaluation.get("n_test"),
                    "n_train": self.evaluation.get("n_train"),
                    "evaluated_at": self.evaluation.get("evaluated_at"),
                    "split": self.evaluation.get("split"),
                    "per_class": self.evaluation.get("per_class", {}),
                    "confusion_matrix": self.evaluation.get("confusion_matrix", {}),
                    "disclaimer": self.evaluation.get("disclaimer"),
                },
            }
        )
        return meta


model_service = ModelService()
