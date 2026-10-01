"""
Idempotent demo bootstrap.

Creates the two demo accounts, registers the bundled held-out CICIDS2017 sample
as a dataset, and - on a completely fresh database - runs one real analysis over
that sample so the dashboard, alerts and charts show genuine pipeline output on
first launch instead of an empty shell.

Nothing here is fabricated: the seeded numbers are produced by running the
production Random Forest over the real held-out sample file.
"""

from __future__ import annotations

from sqlalchemy import func, select

from app.core.config import settings
from app.core.logging import get_logger
from app.core.security import hash_password
from app.db.session import session_scope
from app.models.database_models import AnalysisJob, Dataset, Prediction, User

logger = get_logger("ainids.seed")

SEED_ANALYSIS_ROWS = 1500


def seed_demo_data() -> dict:
    created: dict = {"users": 0, "datasets": 0, "analysis": None}

    with session_scope() as db:
        # ---- users ------------------------------------------------------- #
        for name, email, password, role in (
            ("Security Analyst", settings.DEMO_USER_EMAIL, settings.DEMO_USER_PASSWORD, "analyst"),
            ("System Administrator", settings.DEMO_ADMIN_EMAIL, settings.DEMO_ADMIN_PASSWORD, "admin"),
        ):
            exists = db.scalar(select(User).where(func.lower(User.email) == email.lower()))
            if exists is None:
                db.add(
                    User(name=name, email=email.lower(), password_hash=hash_password(password), role=role)
                )
                created["users"] += 1

        db.commit()
        analyst = db.scalar(select(User).where(func.lower(User.email) == settings.DEMO_USER_EMAIL.lower()))

        # ---- hold-out sample dataset ------------------------------------- #
        sample_dataset = db.scalar(
            select(Dataset).where(Dataset.source == "sample").order_by(Dataset.created_at.asc())
        )
        if sample_dataset is None:
            try:
                from app.services import dataset_service

                sample_dataset = dataset_service.register_builtin_sample(
                    db, "sample_traffic", analyst.id if analyst else None
                )
                created["datasets"] += 1
            except Exception as exc:
                logger.warning("could not register the bundled sample dataset: %s", exc)

        # ---- reference dataset row (statistics only, no stored file) ------ #
        reference = db.scalar(select(Dataset).where(Dataset.source == "reference"))
        if reference is None:
            from app.services.ml_service import model_service

            stats = model_service.reference_stats or {}
            if stats:
                reference = Dataset(
                    filename="CICIDS2017 (MachineLearningCVE) - full reference capture",
                    stored_path=None,
                    uploaded_by=None,
                    rows=int(stats.get("full_dataset_rows") or 0),
                    columns=int(stats.get("full_dataset_columns") or 0),
                    size_bytes=0,
                    status="reference",
                    source="reference",
                    target_column=stats.get("target_column", "Attack Type"),
                    attack_categories=sorted((stats.get("class_counts_full_dataset") or {}).keys()),
                    missing_values=0,
                    duplicate_rows=int(stats.get("duplicate_rows_within_batches") or 0),
                    numerical_columns=len(stats.get("columns", [])),
                    categorical_columns=1,
                    feature_coverage=1.0,
                    schema_matched=True,
                    class_distribution=stats.get("class_counts_full_dataset") or {},
                    sample_rows=[],
                )
                db.add(reference)
                created["datasets"] += 1

        db.commit()

        # ---- one real bootstrap analysis --------------------------------- #
        job_count = int(db.scalar(select(func.count(AnalysisJob.id))) or 0)
        prediction_count = int(db.scalar(select(func.count(Prediction.id))) or 0)
        if job_count == 0 and prediction_count == 0 and sample_dataset is not None:
            try:
                from app.services import prediction_service

                job = prediction_service.create_job(db, sample_dataset, analyst.id if analyst else None)
                summary = prediction_service.run_analysis(
                    db, job, sample_dataset, user_id=analyst.id if analyst else None, source="sample"
                )
                created["analysis"] = summary
                logger.info(
                    "bootstrap analysis complete: %s flows, %s suspicious, %s alerts",
                    summary["total_records"],
                    summary["suspicious_records"],
                    summary["alerts_generated"],
                )
            except Exception as exc:
                logger.warning("bootstrap analysis skipped: %s", exc)

    if created["users"] or created["datasets"] or created["analysis"]:
        logger.info(
            "demo seed: %d user(s), %d dataset(s), bootstrap analysis=%s",
            created["users"],
            created["datasets"],
            "yes" if created["analysis"] else "no",
        )
    return created


if __name__ == "__main__":  # python -m app.db.seed
    from app.db.session import init_db

    init_db()
    result = seed_demo_data()
    print(
        f"seeded users={result['users']} datasets={result['datasets']} "
        f"analysis={'yes' if result['analysis'] else 'no'}"
    )
