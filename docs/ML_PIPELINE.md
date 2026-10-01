# ML pipeline

Three scripts, run in order. None of them runs inside the API: training is an offline step, and the
backend only *loads* what they produce.

```
ml/build_dataset.py   raw CICIDS2017  →  data/processed/cicids2017_subset.parquet
                                      →  ml/artifacts/{label_codes,dataset_stats}.json
ml/train_model.py     processed table  →  ml/artifacts/* + backend/app/ml/*
                                      →  frontend/public/samples/*.csv
ml/build_profiles.py  processed table  →  ml/artifacts/class_profiles.json
```

## 1. Build the dataset

```bash
python ml/build_dataset.py --download          # fetch the 8 per-day parquet files (~257 MB) to /tmp/cicids2017
python ml/build_dataset.py                     # --mode subset (default)
python ml/build_dataset.py --mode full         # keep every cleaned row (needs ≥ 8 GB RAM)
```

What happens per file, in batches (bounded memory — the largest file is 692 703 rows):

1. header whitespace/BOM canonicalised; the duplicated `Fwd Header Length_duplicated_0` column from
   the original CSVs is unified with `Fwd Header Length`;
2. `Label` mapped through `cicids_config.LABEL_TO_ATTACK_TYPE` to one of 10 categories;
3. `±∞ → NaN`, `NaN` rows dropped; per-column null counts accumulated for the full-capture statistics;
4. duplicate rows removed within each batch (142 733 duplicates exist in the raw capture);
5. **stratified reservoir sampling**: Normal Traffic 120 000, DoS/PortScan/DDoS 30 000 each, every
   other attack family up to 20 000 (small families are kept in full);
6. exactly constant columns dropped (8 `*_Flags` / `*Avg …/Bulk` columns);
7. remainder written to Parquet as float32 + int16 label code (`data/processed/…`, 25 MB).

Sampling exists so the table trains on a laptop. It changes class priors — that is documented in
`dataset_stats.json` and repeated in the README and on the AI Model page.

## 2. Train and export

```bash
python ml/train_model.py                       # defaults: 100 trees, min_samples_leaf=2, 70/30 split, seed 42
python ml/train_model.py --trees 200 --test-size 0.25
python ml/train_model.py --no-size-guard       # default fully-grown trees (~1 GB artifact)
```

`train_model.py` fits `RandomForestClassifier`, evaluates on the held-out split
(accuracy, macro/weighted F1, per-class precision/recall/F1/support, confusion matrix with labels and
timings), then writes **every artifact the backend reads** — model, feature order, label mapping,
preprocessing config, model card, evaluation, importances — plus the two demo CSVs (1 500 and 800
held-out flows). Finally it copies the artifacts into `backend/app/ml/` so the API picks them up on
its next restart.

Artifacts the API depends on:

| File | Consumed by |
| --- | --- |
| `random_forest_model.joblib` | `ml_service` (loaded once at startup) |
| `feature_columns.json` | `preprocessing_service` (order + coverage contract) |
| `preprocessing_config.json` | imputation medians, inf handling, `min_feature_coverage` |
| `label_mapping.json` | index → class name, `normal_class`, detailed labels → categories |
| `model_metadata.json` | `/api/model/info`, `/api/model/architecture`, model card UI |
| `evaluation.json` | `/api/model/evaluation`, the accuracy label shown in the UI |
| `feature_importance.json` | `/api/model/features`, "Top Model Features" chart |
| `dataset_stats.json` | `/api/datasets/reference`, Dataset Explorer reference card |

Delete any one of them and the corresponding page will say so instead of inventing values; delete the
joblib file and the API refuses to start.

## 3. Class profiles

```bash
python ml/build_profiles.py        # 9 classes × 30 features: median, mean, p95, max, normal_median, ratio
```

Used as *evidence* in explanations ("this flow's average packet size is 8.7× the normal median") and
rendered on the AI Model page. It is descriptive statistics of the training table — not a model.

## Reproducibility

Everything derives from `--seed 42` (sampling + split + forest). Re-running the three scripts on the
same raw files reproduces the same artifacts; only the timestamps in metadata/evaluation change.
Recorded environment: Python 3.13.14, scikit-learn 1.6.1, pandas 2.2.3, numpy 2.3.5, shap 0.52.0.

## Measured results on the shipped artifacts

| Metric | Value |
| --- | ---: |
| Training table | 217 731 × 70 |
| Split | 152 411 train / 65 320 test |
| Accuracy | 0.9959430496019596 |
| Macro F1 | 0.981756145538863 |
| Weighted F1 | 0.9959430496019596 |
| Weakest classes | Infiltration (recall 0.8182), Bot (recall 0.9521) |
| Model size | 4.34 MB |

These are lab-split results on a 2017 capture (see README §22) — the app displays them with that
disclaimer attached, and never as a promise of real-world performance.
