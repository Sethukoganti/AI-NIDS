"""
Shared configuration for the AI-NIDS machine-learning pipeline.

This module is the single source of truth for:
  * where the raw CICIDS2017 files come from,
  * how raw CICIDS2017 ``Label`` values map onto the ``Attack Type`` target,
  * which columns are treated as features,
  * the sampling / split / model hyper-parameters.

Both the offline training scripts (``ml/``) and the online inference service
(``backend/app/services/preprocessing_service.py``) must agree on this
contract.  Nothing here may be changed without retraining the model.
"""

from __future__ import annotations

import json
from pathlib import Path

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
ROOT = Path(__file__).resolve().parent.parent

RAW_DIR = ROOT / "data" / "raw"            # downloaded CICIDS2017 *.parquet / *.csv
PROCESSED_DIR = ROOT / "data" / "processed"  # cleaned training table
ARTIFACT_DIR = ROOT / "ml" / "artifacts"     # model registry (exported to backend)

PROCESSED_TABLE = PROCESSED_DIR / "cicids2017_subset.parquet"
DATASET_STATS = PROCESSED_DIR / "dataset_stats.json"

# Canonical public mirror of the CICIDS2017 *MachineLearningCVE* flow CSVs.
# The original host (iscxdownloads.cs.unb.ca) is not always reachable, so the
# pipeline supports several mirrors.  Files are stored as parquet mirrors of the
# original CSVs (identical values, identical column names).
DATASET_SOURCES = [
    "https://huggingface.co/datasets/bvsam/cic-ids-2017/resolve/main/machine_learning/{name}",
    "https://huggingface.co/datasets/bencorn/CICIDS2017/resolve/main/csvs/{zip_name}",
]

# The eight MachineLearningCVE flow files that make up CICIDS2017.
CICIDS_FILES = [
    "Monday-WorkingHours.pcap_ISCX.csv.parquet",
    "Tuesday-WorkingHours.pcap_ISCX.csv.parquet",
    "Wednesday-workingHours.pcap_ISCX.csv.parquet",
    "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv.parquet",
    "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv.parquet",
    "Friday-WorkingHours-Morning.pcap_ISCX.csv.parquet",
    "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv.parquet",
    "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv.parquet",
]

TARGET_COLUMN = "Attack Type"
SOURCE_LABEL_COLUMN = "Label"

# --------------------------------------------------------------------------- #
# Target mapping: raw CICIDS2017 Label -> Attack Type category
#
# This mirrors the widely used CICIDS2017 grouping: the 15 fine-grained labels
# published by the Canadian Institute for Cybersecurity are grouped into 10
# human-readable traffic categories.  "Normal Traffic" replaces "BENIGN".
# --------------------------------------------------------------------------- #
LABEL_TO_ATTACK_TYPE = {
    "BENIGN": "Normal Traffic",
    "PortScan": "Port Scanning",
    "DDoS": "DDoS",
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "FTP-Patator": "Brute Force",
    "SSH-Patator": "Brute Force",
    "Bot": "Bot",
    # The published CSV used a non-UTF8 dash in the Web Attack labels.
    "Web Attack \ufffd Brute Force": "Web Attack",
    "Web Attack \ufffd XSS": "Web Attack",
    "Web Attack \ufffd Sql Injection": "Web Attack",
    "Web Attack – Brute Force": "Web Attack",
    "Web Attack – XSS": "Web Attack",
    "Web Attack – Sql Injection": "Web Attack",
    "Web Attack - Brute Force": "Web Attack",
    "Web Attack - XSS": "Web Attack",
    "Web Attack - Sql Injection": "Web Attack",
    "Infiltration": "Infiltration",
    "Heartbleed": "Heartbleed",
}

NORMAL_CLASS = "Normal Traffic"

# --------------------------------------------------------------------------- #
# Feature schema (the 78 MachineLearningCVE flow features, in file order)
# --------------------------------------------------------------------------- #
FEATURE_COLUMNS: list[str] = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Header Length_duplicated_0",  # duplicate column present in the published CSV
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]

# Columns that are known to carry no information in the published CSV
# (constant / all-zero / duplicated in the source file).  They are detected
# empirically during dataset build *and* listed here as a fallback so inference
# never depends on a column the model was not trained on.
KNOWN_UNINFORMATIVE_COLUMNS = {
    "Fwd Header Length_duplicated_0",
    "Bwd PSH Flags",
    "Bwd URG Flags",
    "CWE Flag Count",
    "ECE Flag Count",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
}

# Minimum share of the model's expected features that an uploaded file must
# provide before it is accepted for inference.
MIN_FEATURE_COVERAGE = 0.80

# Maximum number of categorical levels that are one-hot encoded at inference
# time (guards against exploding the feature space on hostile uploads).
MAX_ONEHOT_LEVELS = 20

# --------------------------------------------------------------------------- #
# Sampling + training hyper-parameters (documented in README / model metadata)
# --------------------------------------------------------------------------- #
RANDOM_STATE = 42
TEST_SIZE = 0.3
N_ESTIMATORS = 100

# Deterministic stratified subsample used to keep training tractable on a
# laptop while still exercising every attack family in the dataset.
# Keys are *Attack Type* categories (post-mapping), not raw Label spellings.
# ``None`` means "keep every row of that class".
PER_CLASS_CAP_SUBSET: dict[str, int | None] = {
    "Normal Traffic": 120_000,
    "DoS": 30_000,
    "Port Scanning": 30_000,
    "DDoS": 30_000,
}
DEFAULT_CLASS_CAP_SUBSET = 20_000  # applies to classes absent from the dict above

# Tree-size guard.  ``min_samples_leaf=1`` (the scikit-learn default) produces
# ~1 GB of serialized trees on this data volume, which is unusable for a web
# service.  Increasing it is a documented size/robustness trade-off; the
# algorithm stays a Random Forest and the accuracy impact is measured and
# reported in ``model_metadata.json``.  ``--no-size-guard`` in train_model.py
# reproduces the pure defaults.
MIN_SAMPLES_LEAF = 2

# --------------------------------------------------------------------------- #
# Risk engine thresholds (used by backend/app/services/risk_service.py)
# Kept here as well so the training report and the API agree on the rules.
# --------------------------------------------------------------------------- #
RISK_RULES = {
    "critical_score": 0.96,
    "high_score": 0.85,
    "medium_score": 0.65,
    "formula": "attack_severity_weight[prediction] * confidence + sensitive_port_bonus",
}


def canonical_column(name: str) -> str:
    """Normalise a raw header to the canonical CICIDS2017 column name.

    The published CSV contains stray leading/trailing spaces (``" Label"``) and
    is inconsistent about capitalisation in a few mirrors.
    """
    return " ".join(name.replace("\ufeff", "").strip().split())


CANONICAL_LOOKUP = {c.lower(): c for c in FEATURE_COLUMNS}
CANONICAL_LOOKUP[SOURCE_LABEL_COLUMN.lower()] = SOURCE_LABEL_COLUMN
CANONICAL_LOOKUP[TARGET_COLUMN.lower()] = TARGET_COLUMN


def to_canonical(name: str) -> str:
    """Map an arbitrary header spelling onto the canonical name when possible."""
    cleaned = canonical_column(name)
    return CANONICAL_LOOKUP.get(cleaned.lower(), cleaned)


def load_json(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)
