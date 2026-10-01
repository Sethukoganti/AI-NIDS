"""
Preprocessing / feature-alignment service.

Responsibilities
----------------
* Read a traffic file (CSV / parquet) defensively (size, encoding, structure).
* Canonicalise headers and profile the data (rows, columns, missing, duplicates).
* Validate the upload against the *exact* feature schema the model was trained
  on - never send arbitrary columns to the model.
* Build the feature matrix in the trained column order, one-hot encoding any
  bounded categorical columns, and imputing expected-but-absent features with
  the training-split medians (always reported back to the caller).
* Surface ground-truth labels / timestamps / IP columns when the file has them.

Nothing here re-trains or re-fits anything: this is pure feature preparation.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np
import pandas as pd

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("ainids.preprocessing")

# Columns that are never model features, even if a file ships them.
NON_FEATURE_HINTS = {
    "label",
    "attack type",
    "class",
    "target",
    "id",
    "flow id",
    "source ip",
    "destination ip",
    "src ip",
    "dst ip",
    "source",
    "destination",
    "timestamp",
    "time",
    "flow start time",
    "flow end time",
    "date",
    "category",
}
TIMESTAMP_CANDIDATES = ["timestamp", "time", "flow start time", "start time", "date", "ts"]
SOURCE_PORT_CANDIDATES = ["source port", "src port", "sport"]
DEST_PORT_CANDIDATES = ["destination port", "dst port", "dport"]
SRC_IP_CANDIDATES = ["source ip", "src ip", "source", "srcip"]
DST_IP_CANDIDATES = ["destination ip", "dst ip", "destination", "dstip"]
PROTOCOL_CANDIDATES = ["protocol", "proto"]


class DatasetError(Exception):
    """Raised with a user-facing message when a file cannot be analysed."""

    def __init__(self, message: str, status_code: int = 400, detail: dict | None = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.detail = detail or {}


@dataclass
class Schema:
    """The model's expected feature schema (loaded once from feature_columns.json)."""

    feature_columns: list[str]
    target_column: str
    source_label_column: str
    min_feature_coverage: float
    max_onehot_levels: int
    dropped_columns: list[str] = field(default_factory=list)
    feature_medians: dict[str, float] = field(default_factory=dict)
    label_to_category: dict[str, str] = field(default_factory=dict)

    @property
    def lookup(self) -> dict[str, str]:
        return {c.strip().lower(): c for c in self.feature_columns}


def _canonical(name: str) -> str:
    return " ".join(str(name).replace("\ufeff", "").strip().split())


def load_schema() -> Schema:
    from app.services.ml_service import model_service

    fc = model_service.feature_columns
    meta = model_service.metadata
    prep = model_service.preprocessing_config
    mapping = model_service.label_mapping
    return Schema(
        feature_columns=list(fc["feature_columns"]),
        target_column=fc.get("target_column", "Attack Type"),
        source_label_column=fc.get("source_label_column", "Label"),
        min_feature_coverage=float(fc.get("min_feature_coverage", 0.8)),
        max_onehot_levels=int(fc.get("max_onehot_levels", 20)),
        dropped_columns=list(fc.get("dropped_columns", [])),
        feature_medians={k: float(v) for k, v in (prep.get("feature_medians") or {}).items()},
        label_to_category={
            str(k).strip(): str(v) for k, v in (mapping.get("detailed_label_to_category") or {}).items()
        },
    )


# --------------------------------------------------------------------------- #
# Reading
# --------------------------------------------------------------------------- #
def read_traffic_file(path: Path, max_rows: int | None = None) -> pd.DataFrame:
    """Read a CSV/parquet traffic file with defensive handling."""
    if not path.exists():
        raise DatasetError("The uploaded file could not be found on the server.", 404)

    size = path.stat().st_size
    if size == 0:
        raise DatasetError("The uploaded dataset contains no records.")
    if size > settings.MAX_UPLOAD_SIZE:
        raise DatasetError(
            f"File is too large ({size / 1e6:.1f} MB). Maximum allowed is "
            f"{settings.MAX_UPLOAD_SIZE / 1e6:.1f} MB."
        )

    suffix = path.suffix.lower()
    try:
        if suffix in {".parquet", ".pq"}:
            df = pd.read_parquet(path)
        else:
            df = None
            last_error: Exception | None = None
            attempts = (
                {"sep": ",", "engine": "c"},        # canonical CICIDS2017 machine-learning CSV
                {"sep": ";", "engine": "c"},
                {"sep": "\t", "engine": "c"},
                {"sep": None, "engine": "python"},  # last resort: sniff the delimiter
            )
            for encoding in ("utf-8", "latin-1", "cp1252"):
                for kwargs in attempts:
                    try:
                        candidate = pd.read_csv(
                            path, encoding=encoding, low_memory=False,
                            on_bad_lines="skip", **kwargs
                        )
                    except (UnicodeDecodeError, pd.errors.ParserError, ValueError, pd.errors.EmptyDataError) as exc:
                        last_error = exc
                        continue
                    if candidate is not None and candidate.shape[1] >= 2 and not candidate.empty:
                        df = candidate
                        break
                if df is not None:
                    break
            if df is None:
                raise DatasetError(
                    "Invalid file format. Please upload a CSV file with a header row.",
                    400,
                    {
                        "reason": str(last_error)[:200] if last_error else "unreadable",
                        "hint": "Expected a delimited text file with a header row "
                                "(CICIDS2017 MachineLearningCVE CSV or an equivalent flow export).",
                    },
                )
    except DatasetError:
        raise
    except Exception as exc:  # pragma: no cover - corrupted input
        logger.warning("failed to parse upload: %s", type(exc).__name__)
        raise DatasetError("Invalid file format. Please upload a CSV file.") from exc

    if df is None or df.empty:
        raise DatasetError("The uploaded dataset contains no records.")
    if df.shape[1] < 2:
        raise DatasetError(
            "Invalid file format. Please upload a CSV file with a header row.",
            400,
            {"reason": "fewer than two columns detected"},
        )

    df = df.rename(columns={c: _canonical(c) for c in df.columns})
    # drop fully-empty trailing columns produced by a trailing separator
    df = df.loc[:, [c for c in df.columns if not c.lower().startswith("unnamed")]]
    if max_rows is not None and len(df) > max_rows:
        df = df.head(max_rows)
    return df


# --------------------------------------------------------------------------- #
# Profiling (used by the Dataset Explorer + upload validation)
# --------------------------------------------------------------------------- #
def profile_dataframe(df: pd.DataFrame, schema: Schema, class_distribution: bool = True) -> dict:
    numeric_cols, categorical_cols = [], []
    for col in df.columns:
        if pd.api.types.is_numeric_dtype(df[col]):
            numeric_cols.append(col)
        else:
            # numeric-looking strings count as numeric
            coerced = pd.to_numeric(df[col], errors="coerce")
            (numeric_cols if coerced.notna().mean() >= 0.9 else categorical_cols).append(col)

    label_col = _find_column(df, [schema.source_label_column, schema.target_column])
    distribution: dict[str, int] = {}
    if class_distribution and label_col:
        series = df[label_col].astype(str).str.strip()
        mapped = series.map(lambda v: schema.label_to_category.get(v, v))
        distribution = {str(k): int(v) for k, v in mapped.value_counts().head(30).items()}

    columns_meta = []
    expected = set(schema.feature_columns)
    for col in df.columns:
        series = df[col]
        entry = {
            "name": col,
            "dtype": str(series.dtype),
            "role": "feature" if col in expected else ("target" if col in (label_col, schema.target_column) else "auxiliary"),
            "missing": int(series.isna().sum()),
            "unique": int(series.nunique(dropna=True)),
        }
        if col in numeric_cols:
            numeric = pd.to_numeric(series, errors="coerce")
            entry.update(
                {
                    "type": "numeric",
                    "min": _safe(float(numeric.min())),
                    "max": _safe(float(numeric.max())),
                    "mean": _safe(float(numeric.mean())),
                    "std": _safe(float(numeric.std())),
                }
            )
        else:
            entry.update({"type": "categorical", "top_values": series.astype(str).value_counts().head(5).to_dict()})
        columns_meta.append(entry)

    matched, missing = match_features(df.columns.tolist(), schema)
    return {
        "rows": int(len(df)),
        "columns": int(df.shape[1]),
        "numerical_columns": len(numeric_cols),
        "categorical_columns": len(categorical_cols),
        "missing_values": int(df.isna().sum().sum()),
        "duplicate_rows": int(df.duplicated().sum()),
        "target_column": label_col,
        "class_distribution": distribution,
        "columns_meta": columns_meta,
        "matched_features": matched,
        "missing_features": missing,
        "feature_coverage": round(len(matched) / max(len(schema.feature_columns), 1), 4),
    }


def _safe(value: float) -> float | None:
    return None if value is None or not math.isfinite(value) else round(value, 6)


def match_features(columns: list[str], schema: Schema) -> tuple[list[str], list[str]]:
    """Compare uploaded columns against the trained feature set."""
    lookup = schema.lookup
    present = set()
    for col in columns:
        key = col.strip().lower()
        if key in lookup:
            present.add(lookup[key])
        elif key in schema.label_to_category:
            continue
    matched = [c for c in schema.feature_columns if c in present]
    missing = [c for c in schema.feature_columns if c not in present]
    return matched, missing


def _find_column(df: pd.DataFrame, candidates: list[str]) -> str | None:
    lower = {c.strip().lower(): c for c in df.columns}
    for cand in candidates:
        if cand.strip().lower() in lower:
            return lower[cand.strip().lower()]
    return None


# --------------------------------------------------------------------------- #
# Feature preparation
# --------------------------------------------------------------------------- #
@dataclass
class PreparedData:
    features: pd.DataFrame           # aligned, ordered, float32 feature matrix
    diagnostics: dict                # what happened during preparation
    ground_truth: list[str | None]   # per-row raw Label (or mapping), when available
    event_times: list[str | None]
    row_meta: dict                   # per-row display metadata (ports, ips, protocol)


def prepare_features(df: pd.DataFrame, schema: Schema, strict: bool = True) -> PreparedData:
    """
    Turn a raw dataframe into the feature matrix the model expects.

    Raises ``DatasetError`` when the file is not a network-flow file at all.
    """
    columns = df.columns.tolist()
    matched, missing = match_features(columns, schema)
    coverage = len(matched) / max(len(schema.feature_columns), 1)

    if not matched:
        raise DatasetError(
            "This dataset is incompatible with the current model because required "
            "network-flow features are missing.",
            400,
            {
                "matched_features": 0,
                "expected_features": len(schema.feature_columns),
                "missing_features": missing[:25],
                "hint": "Upload a CICIDS2017-compatible network-flow CSV (MachineLearningCVE "
                        "feature set) or export flows with the same feature names.",
            },
        )
    if strict and coverage < schema.min_feature_coverage:
        raise DatasetError(
            "This dataset is incompatible with the current model because required "
            "network-flow features are missing.",
            400,
            {
                "matched_features": len(matched),
                "expected_features": len(schema.feature_columns),
                "coverage": round(coverage, 4),
                "required_coverage": schema.min_feature_coverage,
                "missing_features": missing[:25],
            },
        )

    # ---- build the aligned frame ----------------------------------------- #
    canonical = {c.strip().lower(): c for c in columns}
    lookup = schema.lookup
    aligned = pd.DataFrame(index=df.index)

    imputed: list[str] = []
    for feature in schema.feature_columns:
        source = lookup.get(feature.strip().lower())
        col = canonical.get((source or feature).strip().lower())
        if col is not None and col in df.columns:
            aligned[feature] = pd.to_numeric(df[col], errors="coerce")
        else:
            aligned[feature] = np.nan
            imputed.append(feature)

    # ---- bounded one-hot encoding for categorical flow exports ----------- #
    onehot_created: list[str] = []
    for col in columns:
        if col in matched or col.strip().lower() in NON_FEATURE_HINTS:
            continue
        series = df[col]
        if pd.api.types.is_numeric_dtype(series):
            continue
        can_be_numeric = pd.to_numeric(series, errors="coerce").notna().mean() >= 0.9
        if can_be_numeric:
            continue
        levels = series.astype(str).str.strip().unique()
        if 1 < len(levels) <= schema.max_onehot_levels:
            for level in levels:
                candidate = f"{col}_{level}"
                target = lookup.get(candidate.strip().lower())
                if target and target in aligned.columns and aligned[target].isna().all():
                    aligned[target] = (series.astype(str).str.strip() == level).astype(float)
                    onehot_created.append(target)

    # ---- cleaning identical to training-time policy ---------------------- #
    replaced_inf = int(np.isinf(aligned.to_numpy(dtype="float64", copy=False)).sum())
    aligned = aligned.replace([np.inf, -np.inf], np.nan)

    rows_before = len(aligned)
    notna_mask = aligned.notna().all(axis=1)
    dropped_nan = int((~notna_mask).sum())
    aligned = aligned[notna_mask]

    if aligned.empty:
        raise DatasetError(
            "No analysable flow records found: every row was missing required feature "
            "values or contained only infinite values.",
            400,
            {
                "rows_in_file": rows_before,
                "dropped_missing_values": dropped_nan,
                "replaced_infinite_values": replaced_inf,
            },
        )

    # ---- impute expected-but-absent features with training medians ------- #
    imputed_features: list[str] = []
    for feature in schema.feature_columns:
        if aligned[feature].isna().all():
            aligned[feature] = float(schema.feature_medians.get(feature, 0.0))
            imputed_features.append(feature)
        elif aligned[feature].isna().any():
            aligned[feature] = aligned[feature].fillna(float(schema.feature_medians.get(feature, 0.0)))
            if feature not in imputed_features:
                imputed_features.append(f"{feature} (partial)")

    aligned = aligned.astype("float32")

    # ---- per-row display metadata ---------------------------------------- #
    row_meta = _extract_row_meta(df, aligned.index)
    ground_truth = _extract_ground_truth(df, aligned.index, schema)
    event_times = _extract_timestamps(df, aligned.index)

    diagnostics = {
        "rows_in_file": rows_before,
        "rows_usable": int(len(aligned)),
        "rows_dropped_missing_values": dropped_nan,
        "infinite_values_replaced": replaced_inf,
        "matched_features": len(matched),
        "expected_features": len(schema.feature_columns),
        "feature_coverage": round(coverage, 4),
        "missing_features": missing,
        "imputed_features": imputed_features,
        "onehot_features_created": onehot_created,
        "expected_but_absent": imputed,
        "extra_columns_ignored": [
            c for c in columns
            if c not in matched and c.strip().lower() not in NON_FEATURE_HINTS and c not in onehot_created
        ][:40],
        "deduplicated": False,
        "feature_order": schema.feature_columns,
    }
    return PreparedData(
        features=aligned,
        diagnostics=diagnostics,
        ground_truth=ground_truth,
        event_times=event_times,
        row_meta=row_meta,
    )


def _extract_row_meta(df: pd.DataFrame, index: pd.Index) -> dict:
    def numeric_col(candidates: list[str]) -> pd.Series | None:
        col = _find_column(df, candidates)
        if col is None:
            return None
        return pd.to_numeric(df.loc[index, col], errors="coerce")

    def text_col(candidates: list[str]) -> pd.Series | None:
        col = _find_column(df, candidates)
        if col is None:
            return None
        return df.loc[index, col].astype(str).str.strip()

    return {
        "source_port": numeric_col(SOURCE_PORT_CANDIDATES),
        "destination_port": numeric_col(DEST_PORT_CANDIDATES),
        "source_ip": text_col(SRC_IP_CANDIDATES),
        "destination_ip": text_col(DST_IP_CANDIDATES),
        "protocol": text_col(PROTOCOL_CANDIDATES),
    }


def _extract_ground_truth(df: pd.DataFrame, index: pd.Index, schema: Schema) -> list[str | None]:
    """Return per-row ground truth (mapped to Attack Type) when the file ships labels."""
    col = _find_column(df, [schema.source_label_column, schema.target_column])
    if col is None:
        return [None] * len(index)
    series = df.loc[index, col].astype(str).str.strip()
    return [
        schema.label_to_category.get(value, value) if value and value.lower() != "nan" else None
        for value in series.tolist()
    ]


def _extract_timestamps(df: pd.DataFrame, index: pd.Index) -> list[str | None]:
    col = _find_column(df, TIMESTAMP_CANDIDATES)
    if col is None:
        return [None] * len(index)
    parsed = pd.to_datetime(df.loc[index, col], errors="coerce")
    return [
        None if pd.isna(ts) else (ts.isoformat() if hasattr(ts, "isoformat") else str(ts))
        for ts in parsed.tolist()
    ]


def load_reference_stats() -> dict:
    path = Path(settings.DATASET_STATS_PATH)
    if not path.exists():
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)
