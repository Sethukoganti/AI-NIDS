"""Model API - everything the 'AI Model' page renders, straight from the artifacts."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from app.core.security import get_current_user
from app.services.ml_service import ModelUnavailableError, model_service

router = APIRouter(prefix="/model", tags=["model"])


@router.get("/info", summary="Model card: algorithm, dataset, split, measured accuracy")
def info(user=Depends(get_current_user)):
    return model_service.info()


@router.get("/features", summary="Feature importance from model.feature_importances_")
def features(
    top: int = Query(20, ge=1, le=200, description="How many features to return"),
    user=Depends(get_current_user),
):
    try:
        return model_service.importance(top=top)
    except ModelUnavailableError as exc:
        raise HTTPException(status_code=503, detail={"message": str(exc)}) from exc


@router.get("/evaluation", summary="Held-out evaluation: per-class report + confusion matrix")
def evaluation(user=Depends(get_current_user)):
    if not model_service.evaluation:
        raise HTTPException(
            status_code=503,
            detail={"message": "No evaluation artifact found. Run `python ml/train_model.py`."},
        )
    return model_service.evaluation


@router.get("/architecture", summary="Pipeline diagram data (with the real hyper-parameters)")
def architecture(user=Depends(get_current_user)):
    metadata = model_service.metadata
    evaluation = model_service.evaluation
    stats = model_service.reference_stats or {}
    return {
        "stages": [
            {
                "id": "dataset",
                "name": "CICIDS2017",
                "detail": f"{stats.get('full_dataset_rows', 0):,} labelled flows x "
                          f"{stats.get('full_dataset_columns', 0)} columns (MachineLearningCVE)",
                "metrics": {"source_files": len(stats.get("source_files", {}))},
            },
            {
                "id": "preprocessing",
                "name": "Preprocessing",
                "detail": "inf -> NaN, drop NaN rows, drop duplicate flows, drop constant "
                          "columns, label mapping to Attack Type",
                "metrics": {
                    "rows_after_cleaning": stats.get("rows_after_cleaning"),
                    "dropped_constant_columns": len(stats.get("dropped_constant_columns", [])),
                },
            },
            {
                "id": "features",
                "name": "Feature Matrix",
                "detail": f"{len(model_service.feature_names())} numeric flow features in the "
                          "exact trained column order (one-hot guard for categorical exports)",
                "metrics": {"n_features": len(model_service.feature_names())},
            },
            {
                "id": "sampling",
                "name": "Stratified sampling",
                "detail": "every attack family retained; BENIGN and the three largest families capped",
                "metrics": {"training_rows": (metadata.get("training_table") or {}).get("rows")},
            },
            {
                "id": "split",
                "name": "Train / Test split",
                "detail": f"{int((metadata.get('train_split') or 0) * 100)}% / "
                          f"{int((metadata.get('test_split') or 0) * 100)}%, stratified, random_state=42",
                "metrics": {"n_train": evaluation.get("n_train"), "n_test": evaluation.get("n_test")},
            },
            {
                "id": "forest",
                "name": f"Random Forest ({metadata.get('n_estimators')} decision trees)",
                "detail": "bootstrap samples + random feature subsets per split",
                "metrics": {
                    "n_estimators": metadata.get("n_estimators"),
                    "min_samples_leaf": metadata.get("min_samples_leaf"),
                    "random_state": metadata.get("random_state"),
                },
            },
            {
                "id": "voting",
                "name": "Majority voting / probability averaging",
                "detail": "class with the highest mean predicted probability wins; that mean is the "
                          "reported confidence",
                "metrics": {"n_classes": metadata.get("n_classes")},
            },
            {
                "id": "prediction",
                "name": "Prediction + confidence",
                "detail": f"measured accuracy {evaluation.get('accuracy')} on the held-out test split",
                "metrics": {
                    "accuracy": evaluation.get("accuracy"),
                    "macro_f1": evaluation.get("macro_f1"),
                },
            },
            {
                "id": "risk",
                "name": "Risk engine + alerts",
                "detail": "documented severity weights x confidence, sensitive-port bonus, alert "
                          "threshold at MEDIUM",
                "metrics": {},
            },
        ],
        "algorithm": metadata.get("algorithm"),
        "dataset": metadata.get("dataset"),
        "limitations": metadata.get("limitations", []),
        "evaluation_disclaimer": evaluation.get("disclaimer"),
    }


@router.get("/class-profiles", summary="Per-class medians of the top features (evidence for explanations)")
def class_profiles(user=Depends(get_current_user)):
    from app.services.ai_explanation_service import class_profiles as profiles

    data = profiles()
    if not data:
        raise HTTPException(
            status_code=503,
            detail={"message": "class_profiles.json missing - run `python ml/build_profiles.py`."},
        )
    return data
