"""
Risk engine.

Documented, deterministic rules - no hidden magic. Every level is derived from
(a) the attack family the Random Forest predicted and (b) the model's confidence
in that prediction, with a small, explicit bonus for traffic aimed at
sensitive/administrative ports.

    risk_score = attack_severity_weight[class] * confidence (+ port bonus)

    score >= 0.96            -> CRITICAL   (high-severity family AND near-certain)
    score >= 0.85            -> HIGH
    score >= 0.65            -> MEDIUM
    otherwise                -> LOW

Because the severity weights top out at 1.00 and Port Scanning carries 0.72, a
port scan on its own can never reach CRITICAL - that requires a high-severity
family (DDoS/Infiltration/Heartbleed/Bot) at near-certain confidence, which is
what makes the top level meaningful instead of decorative.

Normal traffic is always LOW: its score only records how *unsure* the model was
(1 - confidence), so a normal flow can never raise an alert on its own.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict

LOW, MEDIUM, HIGH, CRITICAL = "low", "medium", "high", "critical"
LEVEL_ORDER = {LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3}

# Relative severity of each attack family the model can predict (0..1).
# Documented in README -> "Risk classification rules".
ATTACK_SEVERITY_WEIGHT: dict[str, float] = {
    "Infiltration": 1.00,
    "Heartbleed": 0.98,
    "DDoS": 0.95,
    "Bot": 0.92,
    "Web Attack": 0.88,
    "Brute Force": 0.86,
    "DoS": 0.80,
    "Port Scanning": 0.72,
    "Normal Traffic": 0.0,
}
DEFAULT_ATTACK_WEIGHT = 0.75  # unknown/extra class -> treat as a generic attack

# Ports that make an attack flow more urgent (admin/remote access/services).
SENSITIVE_PORTS = {
    21, 22, 23, 25, 110, 135, 139, 143, 445, 993, 995, 1433, 1521, 2049,
    3306, 3389, 5432, 5900, 5985, 5986, 6379, 8080, 8443, 9200, 27017,
}
PORT_BONUS = 0.05
MAX_PORT_BONUS = 0.10

THRESHOLDS = {"critical": 0.96, "high": 0.85, "medium": 0.65}


@dataclass
class RiskAssessment:
    level: str
    score: float
    factors: dict

    def to_dict(self) -> dict:
        return asdict(self)


def assess(
    prediction: str,
    confidence: float,
    is_attack: bool,
    normal_class: str = "Normal Traffic",
    destination_port: float | None = None,
    severity_weight: float | None = None,
    thresholds: dict[str, float] | None = None,
    port_bonus: float = PORT_BONUS,
    max_port_bonus: float = MAX_PORT_BONUS,
) -> RiskAssessment:
    """
    Score one prediction.

    ``thresholds`` / ``port_bonus`` / ``max_port_bonus`` come from the admin
    configuration (see ``config_service.RuntimeConfig``), so the boundary values
    documented above are the *defaults* and the deployed values are whatever the
    admin configured - they are never silently different.
    """
    limits = {**THRESHOLDS, **(thresholds or {})}
    confidence = max(0.0, min(float(confidence or 0.0), 1.0))
    weight = (
        severity_weight
        if severity_weight is not None
        else ATTACK_SEVERITY_WEIGHT.get(prediction, DEFAULT_ATTACK_WEIGHT)
    )

    if not is_attack or prediction == normal_class:
        # A normal prediction: score expresses residual uncertainty only.
        score = round((1.0 - confidence) * 0.4, 6)
        return RiskAssessment(
            level=LOW,
            score=score,
            factors={
                "rule": "normal traffic -> always LOW",
                "model_confidence": round(confidence, 6),
                "residual_uncertainty": round(1.0 - confidence, 6),
                "thresholds": limits,
            },
        )

    score = weight * confidence

    applied_port_bonus = 0.0
    if destination_port is not None and not _is_nan(destination_port) and port_bonus:
        try:
            if int(destination_port) in SENSITIVE_PORTS:
                applied_port_bonus = port_bonus
        except (TypeError, ValueError):
            applied_port_bonus = 0.0
    score = min(score + min(applied_port_bonus, max_port_bonus), 1.0)

    if score >= limits["critical"]:
        level = CRITICAL
    elif score >= limits["high"]:
        level = HIGH
    elif score >= limits["medium"]:
        level = MEDIUM
    else:
        level = LOW

    return RiskAssessment(
        level=level,
        score=round(score, 6),
        factors={
            "rule": "attack_severity_weight * confidence (+ sensitive-port bonus)",
            "attack_severity_weight": weight,
            "model_confidence": round(confidence, 6),
            "port_bonus": round(applied_port_bonus, 4),
            "destination_port": None if _is_nan(destination_port) else int(destination_port),
            "thresholds": limits,
        },
    )


def _is_nan(value) -> bool:
    try:
        return value != value  # NaN check without importing numpy
    except Exception:
        return value is None


def severity_is_at_least(level: str, minimum: str) -> bool:
    return LEVEL_ORDER.get(level, 0) >= LEVEL_ORDER.get(minimum, 0)


def rules_documentation(runtime: dict | None = None) -> dict:
    """
    Exposed through /api/alerts/rules so the UI can show the real rules.

    ``runtime`` is the effective configuration; when omitted the code defaults are
    reported and the payload says so explicitly.
    """
    thresholds = (runtime or {}).get("risk_thresholds") or THRESHOLDS
    port_bonus = (runtime or {}).get("sensitive_port_bonus")
    port_bonus = PORT_BONUS if port_bonus is None else port_bonus
    return {
        "formula": "risk_score = attack_severity_weight[prediction] * confidence + sensitive_port_bonus",
        "thresholds": thresholds,
        "attack_severity_weight": ATTACK_SEVERITY_WEIGHT,
        "default_attack_weight": DEFAULT_ATTACK_WEIGHT,
        "sensitive_ports": sorted(SENSITIVE_PORTS),
        "port_bonus": port_bonus,
        "max_port_bonus": MAX_PORT_BONUS,
        "normal_rule": "predictions equal to the normal class are always LOW risk",
        "alert_rule": "alerts are raised for attack predictions whose risk level is MEDIUM or above",
        "alert_grouping": (
            "qualifying flows are processed highest-risk first; the first flow of each (attack type, "
            "destination port) pair creates that pair's alert, every further flow of the pair is folded "
            "into it (occurrences=N, worst severity kept, prediction_id = highest-risk flow of the pair). "
            "At most one alert exists per pair per job."
        ),
        "alert_volume_cap": (
            "a job produces exactly one alert per distinct attack/port pair of its qualifying flows and "
            "never more than 300 pairs (the rest fold into one overflow alert per attack type), so a "
            "1000-flow port sweep becomes a handful of rows instead of 1000 notifications"
        ),
        "configured": runtime is not None,
        "runtime": runtime or {},
    }
