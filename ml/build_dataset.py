#!/usr/bin/env python3
"""
AI-NIDS - CICIDS2017 dataset builder.

Turns the raw CICIDS2017 *MachineLearningCVE* flow files into the single cleaned
training table used by ``train_model.py``.

Pipeline
--------
read raw files (streamed in batches -> memory safe)
  -> canonicalise column headers (the published CSV has stray spaces/BOM)
  -> map the fine-grained 'Label' onto the 'Attack Type' target
  -> replace +/-inf with NaN                      (documented CICIDS2017 cleaning)
  -> drop rows containing NaN
  -> drop exact duplicate flow records
  -> detect constant / non-informative columns
  -> stratified reservoir subsample (keeps every attack family, caps huge ones)
  -> write data/processed/cicids2017_subset.parquet
  -> write data/processed/dataset_stats.json   (statistics over the FULL dataset)

Memory note
-----------
The fine-grained ground-truth label is carried through as a small integer code
(``Label Code``) rather than a Python string column; the string labels are
rebuilt from ``label_codes.json``.  This keeps a 219k-row build inside ~1 GB.

Usage
-----
    python ml/build_dataset.py --download            # fetch raw files, then build
    python ml/build_dataset.py --mode subset         # default: stratified subsample
    python ml/build_dataset.py --mode full           # every row (needs >= 12 GB RAM)
"""

from __future__ import annotations

import argparse
import json
import math
import time
import urllib.request
from collections import defaultdict
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ml.cicids_config import (  # noqa: E402
    CICIDS_FILES,
    DEFAULT_CLASS_CAP_SUBSET,
    DATASET_SOURCES,
    DATASET_STATS,
    FEATURE_COLUMNS,
    LABEL_TO_ATTACK_TYPE,
    PER_CLASS_CAP_SUBSET,
    PROCESSED_DIR,
    PROCESSED_TABLE,
    RANDOM_STATE,
    SOURCE_LABEL_COLUMN,
    TARGET_COLUMN,
    to_canonical,
)

BATCH_SIZE = 25_000
LABEL_CODE_COLUMN = "Label Code"
LABEL_CODES_FILE = PROCESSED_DIR / "label_codes.json"

# Complete, stable ordering of every raw label in CICIDS2017.
RAW_LABELS = sorted(LABEL_TO_ATTACK_TYPE.keys())
LABEL_CODE = {label: i for i, label in enumerate(RAW_LABELS)}
CODE_LABEL = {str(i): label for label, i in LABEL_CODE.items()}


# --------------------------------------------------------------------------- #
# Download
# --------------------------------------------------------------------------- #
def download_raw(data_dir: Path) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    for name in CICIDS_FILES:
        dest = data_dir / name
        if dest.exists() and dest.stat().st_size > 0:
            print(f"  [skip] {name} already present")
            continue
        url = DATASET_SOURCES[0].format(name=name)
        print(f"  [get ] {name}")
        t0 = time.time()
        urllib.request.urlretrieve(url, dest)  # noqa: S310 (trusted dataset mirror)
        print(f"         {dest.stat().st_size / 1e6:.1f} MB in {time.time() - t0:.1f}s")


# --------------------------------------------------------------------------- #
# Cleaning
# --------------------------------------------------------------------------- #
def clean_batch(df: pd.DataFrame) -> tuple[pd.DataFrame, dict]:
    """Canonicalise, map labels, replace inf, drop NaN rows."""
    df = df.rename(columns={c: to_canonical(str(c)) for c in df.columns})
    stats = {"rows_in": len(df), "nan_rows_dropped": 0}

    label_col = SOURCE_LABEL_COLUMN if SOURCE_LABEL_COLUMN in df.columns else None
    if label_col:
        raw = df[label_col].astype(str).str.strip()
        df[TARGET_COLUMN] = raw.map(LABEL_TO_ATTACK_TYPE)
        unmapped_mask = df[TARGET_COLUMN].isna()
        unmapped = int(unmapped_mask.sum())
        if unmapped:
            print(f"    ! {unmapped:,} rows with an unrecognised Label value were dropped")
            df = df[~unmapped_mask]
            raw = raw.loc[df.index]
        # compact integer ground truth (never a model feature)
        df[LABEL_CODE_COLUMN] = raw.map(LABEL_CODE).fillna(-1).astype("int16")

    feature_cols = [c for c in FEATURE_COLUMNS if c in df.columns]
    numeric = df[feature_cols].apply(pd.to_numeric, errors="coerce")
    numeric = numeric.replace([np.inf, -np.inf], np.nan)

    mask = numeric.notna().all(axis=1)
    stats["nan_rows_dropped"] = int((~mask).sum())
    numeric = numeric[mask]
    df = df.loc[numeric.index]

    numeric = numeric.copy()
    if TARGET_COLUMN in df.columns:
        numeric[TARGET_COLUMN] = df[TARGET_COLUMN].to_numpy()
    if LABEL_CODE_COLUMN in df.columns:
        numeric[LABEL_CODE_COLUMN] = df[LABEL_CODE_COLUMN].to_numpy()
    stats["rows_out"] = len(numeric)
    return numeric, stats


class ConstantColumnDetector:
    """Streaming detector for columns that never vary across the whole dataset."""

    def __init__(self) -> None:
        self.min_: dict[str, float] = {}
        self.max_: dict[str, float] = {}

    def update(self, df: pd.DataFrame) -> None:
        if df.empty:
            return
        for col in df.columns:
            mn, mx = float(df[col].min()), float(df[col].max())
            self.min_[col] = min(self.min_.get(col, math.inf), mn)
            self.max_[col] = max(self.max_.get(col, -math.inf), mx)

    @property
    def constant(self) -> list[str]:
        return sorted(c for c in self.min_ if self.min_[c] == self.max_[c])


class StratifiedReservoir:
    """Deterministic, memory-safe per-class reservoir sampler."""

    def __init__(self, caps: dict[str, int | None], default_cap: int | None, seed: int):
        self.caps = caps
        self.default_cap = default_cap
        self.rng = np.random.default_rng(seed)
        self.reservoirs: dict[str, pd.DataFrame] = {}
        self.seen: dict[str, int] = defaultdict(int)

    def add(self, df: pd.DataFrame) -> None:
        for cls, group in df.groupby(TARGET_COLUMN, sort=False):
            cls = str(cls)
            cap = self.caps.get(cls, self.default_cap)
            group = group.reset_index(drop=True)
            self.seen[cls] += len(group)
            current = self.reservoirs.get(cls)
            if cap is None:
                self.reservoirs[cls] = (
                    group if current is None else pd.concat([current, group], ignore_index=True)
                )
                continue
            if current is None:
                self.reservoirs[cls] = group.sample(
                    n=min(cap, len(group)), random_state=RANDOM_STATE
                ).reset_index(drop=True)
            elif len(current) < cap:
                need = cap - len(current)
                extra = group.sample(n=min(need, len(group)), random_state=RANDOM_STATE)
                self.reservoirs[cls] = pd.concat([current, extra], ignore_index=True)
            else:
                # standard reservoir replacement: each new item lands in the
                # reservoir with probability cap / items_seen
                idx = self.rng.integers(0, self.seen[cls], size=len(group))
                pos = idx[idx < cap]
                if len(pos):
                    self.reservoirs[cls].loc[pos, :] = group.iloc[: len(pos)].to_numpy()


def accumulate_column_stats(acc: dict, df: pd.DataFrame) -> None:
    for col in df.columns:
        values = df[col].to_numpy(dtype="float64", copy=False)
        nan_mask = np.isnan(values)
        n_nan = int(nan_mask.sum())
        entry = acc.setdefault(
            col,
            {"rows": 0, "nan": 0, "min": math.inf, "max": -math.inf, "sum": 0.0, "sumsq": 0.0},
        )
        entry["rows"] += len(values)
        entry["nan"] += n_nan
        if n_nan == len(values):
            continue
        finite = values[~nan_mask]
        entry["min"] = min(entry["min"], float(finite.min()))
        entry["max"] = max(entry["max"], float(finite.max()))
        entry["sum"] += float(finite.sum())
        entry["sumsq"] += float(np.square(finite).sum())


# --------------------------------------------------------------------------- #
# Build
# --------------------------------------------------------------------------- #
def build(mode: str = "subset", raw_dir=None) -> dict:
    project_root = Path(__file__).resolve().parent.parent
    raw_dir = Path(raw_dir) if raw_dir else project_root / "data" / "raw"
    files = sorted(
        f for f in list(raw_dir.glob("*.parquet")) + list(raw_dir.glob("*.csv"))
        if "WorkingHours" in f.name or "workingHours" in f.name
    )
    if not files:
        raise SystemExit(
            f"No CICIDS2017 flow files found in {raw_dir}.\n"
            "Run:  python ml/build_dataset.py --download"
        )

    print(f"Building dataset from {len(files)} file(s)  [mode={mode}]")
    per_file: dict[str, int] = {}
    class_counts_raw: dict[str, int] = defaultdict(int)
    detector = ConstantColumnDetector()
    stats_acc: dict[str, dict] = {}
    dup_rows_within_batches = 0
    rows_after_cleaning = 0

    sampler = (
        StratifiedReservoir({}, None, RANDOM_STATE)
        if mode == "full"
        else StratifiedReservoir(PER_CLASS_CAP_SUBSET, DEFAULT_CLASS_CAP_SUBSET, RANDOM_STATE)
    )

    for path in files:
        print(f"\n>> {path.name}")
        pf = pq.ParquetFile(path)
        per_file[path.name] = pf.metadata.num_rows
        n = nan_dropped = dups = 0
        for batch in pf.iter_batches(batch_size=BATCH_SIZE):
            df = batch.to_pandas()
            if df.empty:
                continue
            n += len(df)
            df, cstats = clean_batch(df)
            nan_dropped += cstats["nan_rows_dropped"]
            if df.empty:
                continue
            rows_after_cleaning += len(df)
            for cls, cnt in df[TARGET_COLUMN].value_counts().items():
                class_counts_raw[str(cls)] += int(cnt)
            before = len(df)
            df = df.drop_duplicates()
            dups += before - len(df)
            if df.empty:
                continue
            feature_view = df.drop(columns=[TARGET_COLUMN, LABEL_CODE_COLUMN], errors="ignore")
            detector.update(feature_view)
            accumulate_column_stats(stats_acc, feature_view)
            sampler.add(df)
            del feature_view
        dup_rows_within_batches += dups
        print(f"   {n:,} rows streamed | {nan_dropped:,} dropped (NaN/inf) | {dups:,} duplicate rows")

    if not sampler.reservoirs:
        raise SystemExit("Sampler produced no rows - check the raw input files.")

    frames = []
    for cls, frame in sampler.reservoirs.items():
        frame = frame.copy()
        frame[TARGET_COLUMN] = cls
        frames.append(frame)
    table = pd.concat(frames, ignore_index=True)

    n_before_dedup = len(table)
    table = table.drop_duplicates().reset_index(drop=True)
    duplicate_rows_after_sampling = n_before_dedup - len(table)

    constant_cols = sorted(set(detector.constant))
    keep_features = [c for c in FEATURE_COLUMNS if c in table.columns and c not in constant_cols]
    dropped_features = [c for c in FEATURE_COLUMNS if c not in keep_features]
    carried = [c for c in (LABEL_CODE_COLUMN,) if c in table.columns]
    table = table[keep_features + carried + [TARGET_COLUMN]]
    table = table.sort_values(TARGET_COLUMN, kind="stable").reset_index(drop=True)

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    table.to_parquet(PROCESSED_TABLE, index=False, compression="zstd")
    LABEL_CODES_FILE.write_text(
        json.dumps(
            {
                "note": "maps the integer 'Label Code' column back to the raw CICIDS2017 Label",
                "code_to_label": CODE_LABEL,
                "label_to_code": LABEL_CODE,
            },
            indent=2,
        )
    )

    class_counts_final = {k: int(v) for k, v in table[TARGET_COLUMN].value_counts().items()}
    stats = {
        "generated_at": pd.Timestamp.utcnow().isoformat() + "Z",
        "mode": mode,
        "source_files": per_file,
        "full_dataset_rows": int(sum(per_file.values())),
        "full_dataset_columns": len(FEATURE_COLUMNS) + 2,
        "rows_after_cleaning": int(rows_after_cleaning),
        "duplicate_rows_within_batches": int(dup_rows_within_batches),
        "duplicate_rows_after_sampling": int(duplicate_rows_after_sampling),
        "class_counts_full_dataset": dict(sorted(class_counts_raw.items(), key=lambda kv: -kv[1])),
        "class_counts_training_table": dict(sorted(class_counts_final.items(), key=lambda kv: -kv[1])),
        "training_rows": int(len(table)),
        "training_columns": int(len(keep_features) + 1 + len(carried)),
        "feature_columns": keep_features,
        "dropped_constant_columns": dropped_features,
        "carried_metadata_columns": carried,
        "target_column": TARGET_COLUMN,
        "attack_categories": sorted(class_counts_final.keys()),
        "columns": [
            {
                "name": col,
                "type": "numeric",
                "missing": int(acc["nan"]),
                "missing_pct": round(100 * acc["nan"] / max(acc["rows"], 1), 6),
                "min": None if acc["min"] == math.inf else acc["min"],
                "max": None if acc["max"] == -math.inf else acc["max"],
                "mean": round(acc["sum"] / max(acc["rows"] - acc["nan"], 1), 6),
                "std": round(
                    math.sqrt(
                        max(
                            acc["sumsq"] / max(acc["rows"] - acc["nan"], 1)
                            - (acc["sum"] / max(acc["rows"] - acc["nan"], 1)) ** 2,
                            0.0,
                        )
                    ),
                    6,
                ),
            }
            for col, acc in sorted(
                stats_acc.items(),
                key=lambda kv: FEATURE_COLUMNS.index(kv[0]) if kv[0] in FEATURE_COLUMNS else 999,
            )
        ],
        "sampling": {
            "strategy": "stratified reservoir sampling" if mode == "subset" else "none (full dataset)",
            "per_class_cap": PER_CLASS_CAP_SUBSET if mode == "subset" else {},
            "default_attack_cap": DEFAULT_CLASS_CAP_SUBSET if mode == "subset" else None,
            "random_state": RANDOM_STATE,
            "note": (
                "BENIGN and the three largest attack families are subsampled so the training "
                "table fits a laptop; every attack family present in CICIDS2017 is retained "
                "(small families are kept in full). Class priors therefore differ from the raw "
                "capture - see docs/ML_PIPELINE.md."
            ),
        },
    }
    DATASET_STATS.write_text(json.dumps(stats, indent=2))

    print("\n" + "=" * 70)
    print(f"Training table : {PROCESSED_TABLE}  ({PROCESSED_TABLE.stat().st_size / 1e6:.1f} MB)")
    print(f"Shape          : {table.shape[0]:,} rows x {table.shape[1]} columns "
          f"({len(keep_features)} features + target + label code)")
    print(f"Constant cols  : {', '.join(constant_cols) if constant_cols else 'none'}")
    print("Class balance  :")
    for cls, cnt in sorted(class_counts_final.items(), key=lambda kv: -kv[1]):
        print(f"   {cls:18s} {cnt:>8,}  {100 * cnt / len(table):6.2f}%")
    print("=" * 70)
    return stats


def main() -> None:
    ap = argparse.ArgumentParser(description="Build the AI-NIDS CICIDS2017 training table")
    ap.add_argument("--download", action="store_true", help="download the raw flow files first")
    ap.add_argument("--mode", choices=["subset", "full"], default="subset")
    ap.add_argument("--raw-dir", default=None)
    args = ap.parse_args()

    if args.download:
        raw_dir = Path(args.raw_dir) if args.raw_dir else Path(__file__).resolve().parent.parent / "data" / "raw"
        print(f"Downloading CICIDS2017 MachineLearningCVE files into {raw_dir}")
        download_raw(raw_dir)
    build(mode=args.mode, raw_dir=args.raw_dir)


if __name__ == "__main__":
    main()
