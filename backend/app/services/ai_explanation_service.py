"""
AI explanation service.

Two layers, both grounded in real model/data output:

1. **Local explanation engine** (always available, no key required)
   Composes an explanation *deterministically* from evidence the ML pipeline
   produced: the predicted class, the model's probabilities, the risk-engine
   factors, per-record TreeSHAP contributions and the CICIDS2017 class profiles
   (real medians computed from the training table). It never invents a fact -
   every sentence maps onto a number in the evidence package.

2. **Optional LLM layer** (``AI_PROVIDER=openai|ollama``)
   The same evidence package is sent to the provider behind the backend, with a
   strict system prompt: use only the supplied evidence, never invent IPs, CVEs
   or events. If the provider is missing, slow or errors, the local engine's
   answer is returned and ``provider`` is reported as a fallback, so the ML
   system is never blocked by the AI layer.
"""

from __future__ import annotations

import json
from typing import Any

from app.core.config import settings
from app.core.logging import get_logger
from app.services.ml_service import model_service

logger = get_logger("ainids.ai")

SYSTEM_PROMPT = (
    "You are the AI Security Assistant inside AI-NIDS, a defensive intrusion-detection "
    "console built on a Random Forest classifier trained on CICIDS2017 network-flow features.\n"
    "You will receive a JSON evidence package produced by the detection system.\n"
    "STRICT RULES:\n"
    "1. Use ONLY the values present in the evidence package. Never invent IP addresses, ports, "
    "hostnames, CVEs, malware names or events that are not in the evidence.\n"
    "2. If the evidence is insufficient to answer, say exactly that and state what is missing.\n"
    "3. Distinguish clearly between (a) what the model predicted, (b) why the model predicted it "
    "(the feature contributions), and (c) general context you are confident about.\n"
    "4. Remember that a prediction is not proof of an attack; the model output is probabilistic "
    "and the accuracy figure is measured on a 2017 research dataset split, not on the live network.\n"
    "5. Write for a college-project audience: precise, plain language, no hype, 120-220 words, "
    "short paragraphs or a compact bullet list."
)


# --------------------------------------------------------------------------- #
# Evidence
# --------------------------------------------------------------------------- #
def build_prediction_evidence(
    prediction: dict,
    shap: dict | None = None,
    ground_truth: str | None = None,
) -> dict:
    """Assemble the structured evidence package for one flow."""
    class_profile = class_profiles().get("profiles", {}).get(prediction.get("prediction", ""), {})
    drivers = []
    for factor in (shap or {}).get("contributions", [])[:6]:
        profile = class_profile.get("features", {}).get(factor["feature"], {})
        drivers.append(
            {
                "feature": factor["feature"],
                "flow_value": round(factor["value"], 4),
                "shap_contribution": round(factor["shap_value"], 6),
                "pushes_towards": factor["direction"],
                "attack_class_median": profile.get("median"),
                "normal_class_median": profile.get("normal_median"),
                "ratio_vs_normal_median": profile.get("ratio_vs_normal_median"),
            }
        )
    if not drivers:
        drivers = [
            {
                "feature": f["feature"],
                "flow_value": round(f["value"], 4),
                "importance": f.get("importance"),
                "deviation_from_training_median": f.get("deviation_from_median"),
                "method": "global_feature_importance_heuristic",
            }
            for f in (prediction.get("top_factors") or [])[:6]
        ]

    return {
        "flow": {
            "record_index": prediction.get("record_index"),
            "source_ip": prediction.get("source_ip") or "not present in the dataset",
            "destination_ip": prediction.get("destination_ip") or "not present in the dataset",
            "source_port": prediction.get("source_port"),
            "destination_port": prediction.get("destination_port"),
            "protocol": prediction.get("protocol"),
            "flow_duration_microseconds": prediction.get("flow_duration"),
            "packets_per_second": prediction.get("packet_rate"),
            "mean_packet_length": prediction.get("packet_length_mean"),
            "total_fwd_packets": prediction.get("total_fwd_packets"),
            "total_bwd_packets": prediction.get("total_bwd_packets"),
        },
        "model_output": {
            "predicted_class": prediction.get("prediction"),
            "confidence": prediction.get("confidence"),
            "is_attack": prediction.get("is_attack"),
            "top_probabilities": prediction.get("top_probabilities", []),
            "algorithm": model_service.metadata.get("algorithm"),
            "n_estimators": model_service.metadata.get("n_estimators"),
            "test_accuracy_on_cicids2017_split": model_service.evaluation.get("accuracy"),
        },
        "risk": {
            "level": prediction.get("risk_level"),
            "score": prediction.get("risk_score"),
            "rules": prediction.get("risk_factors", {}),
        },
        "feature_drivers": drivers,
        "ground_truth_label": ground_truth,
        "limitations": [
            "CICIDS2017 MachineLearningCVE flows contain no IP addresses or timestamps, so "
            "source/destination hosts cannot be identified from this dataset.",
            "The model was trained on a stratified subsample of a 2017 research capture; "
            "performance on current networks is not guaranteed.",
        ],
    }


def class_profiles() -> dict:
    if not model_service.class_profiles:
        from pathlib import Path

        path = Path(settings.DATASET_STATS_PATH).parent / "class_profiles.json"
        model_service.class_profiles = (
            json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        )
    return model_service.class_profiles


# --------------------------------------------------------------------------- #
# Local (deterministic) explanation engine
# --------------------------------------------------------------------------- #
def local_explanation(evidence: dict) -> dict:
    model_output = evidence["model_output"]
    risk = evidence["risk"]
    flow = evidence["flow"]
    predicted = model_output["predicted_class"]
    confidence = (model_output.get("confidence") or 0) * 100
    is_attack = model_output.get("is_attack")

    lines: list[str] = []
    if is_attack:
        lines.append(
            f"The Random Forest classified this flow as **{predicted}** with "
            f"{confidence:.1f}% confidence. The risk engine rated it "
            f"**{str(risk['level']).upper()}** (score {risk.get('score')})."
        )
    else:
        lines.append(
            f"The Random Forest classified this flow as **normal traffic** with "
            f"{confidence:.1f}% confidence, so the risk engine kept it at LOW risk "
            f"(score {risk.get('score')})."
        )

    drivers = evidence.get("feature_drivers") or []
    if drivers:
        parts = []
        for driver in drivers[:4]:
            ratio = driver.get("ratio_vs_normal_median")
            magnitude = f" (≈{ratio:g}× the normal-traffic median)" if ratio else ""
            direction = {
                "attack": "pushed the flow towards an attack class",
                "normal": "pushed the flow towards normal traffic",
            }.get(driver.get("pushes_towards", ""), "contributed to the decision")
            parts.append(f"{driver['feature']} = {driver['flow_value']:,.4g}{magnitude} — {direction}")
        method = "TreeSHAP" if "shap_contribution" in drivers[0] else "global feature importance"
        lines.append(f"Main contributing features ({method}): " + "; ".join(parts) + ".")

    ports = [
        f"source port {flow['source_port']}" if flow.get("source_port") is not None else None,
        f"destination port {flow['destination_port']}" if flow.get("destination_port") is not None else None,
    ]
    port_text = ", ".join(p for p in ports if p)
    if port_text:
        lines.append(f"Flow endpoints observed in the dataset features: {port_text}.")

    if flow.get("source_ip") == "not present in the dataset":
        lines.append(
            "Note: CICIDS2017 MachineLearningCVE flows do not carry IP addresses, so this "
            "console cannot name the hosts involved — only the flow behaviour is available."
        )

    if evidence.get("ground_truth_label"):
        lines.append(
            f"The file's own label for this record is “{evidence['ground_truth_label']}” "
            f"({'agreeing with' if evidence['ground_truth_label'] == predicted else 'disagreeing with'} "
            "the model)."
        )

    ambiguous = sorted(
        model_output.get("top_probabilities", []),
        key=lambda p: -p["probability"],
    )[:2]
    if len(ambiguous) == 2 and ambiguous[0]["probability"] - ambiguous[1]["probability"] < 0.15:
        lines.append(
            f"The decision was close: {ambiguous[0]['class']} "
            f"{ambiguous[0]['probability'] * 100:.1f}% vs {ambiguous[1]['class']} "
            f"{ambiguous[1]['probability'] * 100:.1f}%. Treat it as low-certainty."
        )

    accuracy = model_output.get("test_accuracy_on_cicids2017_split")
    lines.append(
        "Context: this model reports "
        + (f"{accuracy * 100:.2f}% accuracy on the held-out CICIDS2017 test split" if accuracy else "measured test accuracy on CICIDS2017")
        + ", which describes a 2017 lab dataset and is not a guarantee of live-network detection."
    )

    return {
        "provider": "local",
        "provider_label": "Local explanation engine (no external LLM configured)",
        "grounded_on": "model output, risk-engine factors, SHAP/saliency drivers and CICIDS2017 class medians",
        "explanation": "\n\n".join(lines),
        "evidence": evidence,
    }


# --------------------------------------------------------------------------- #
# Optional LLM layer
# --------------------------------------------------------------------------- #
def _llm_complete(prompt: str, evidence: dict) -> str:
    import httpx

    payload = {
        "model": settings.AI_MODEL,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": f"{prompt}\n\nEVIDENCE JSON:\n{json.dumps(evidence, default=str)[:12000]}",
            },
        ],
        "temperature": 0.2,
        "max_tokens": settings.AI_MAX_TOKENS,
    }
    headers = {"Content-Type": "application/json"}
    if settings.AI_API_KEY:
        headers["Authorization"] = f"Bearer {settings.AI_API_KEY}"

    if settings.AI_PROVIDER.lower() == "ollama":
        base = settings.AI_BASE_URL.rstrip("/")
        url = f"{base}/api/chat"
        payload["stream"] = False
        response = httpx.post(url, json=payload, timeout=settings.AI_TIMEOUT_SECONDS)
        response.raise_for_status()
        return response.json()["message"]["content"]

    url = f"{settings.AI_BASE_URL.rstrip('/')}/chat/completions"
    response = httpx.post(url, json=payload, headers=headers, timeout=settings.AI_TIMEOUT_SECONDS)
    response.raise_for_status()
    return response.json()["choices"][0]["message"]["content"]


def explain(evidence: dict, force_local: bool = False) -> dict:
    """Return an explanation, using the LLM when configured and healthy."""
    if force_local or not settings.ai_enabled:
        return local_explanation(evidence)

    try:
        text = _llm_complete(
            "Explain this detection for a security analyst using only the evidence supplied.",
            evidence,
        )
        return {
            "provider": settings.AI_PROVIDER,
            "provider_label": f"{settings.AI_PROVIDER} ({settings.AI_MODEL})",
            "grounded_on": "the same evidence package the local engine uses",
            "explanation": text.strip(),
            "evidence": evidence,
        }
    except Exception as exc:
        logger.warning("AI provider failed (%s); using local explanation engine", type(exc).__name__)
        result = local_explanation(evidence)
        result["provider"] = "local-fallback"
        result["provider_label"] = (
            f"Local explanation engine (AI provider '{settings.AI_PROVIDER}' unavailable: "
            f"{type(exc).__name__})"
        )
        return result


# --------------------------------------------------------------------------- #
# Assistant (question answering over real system data)
# --------------------------------------------------------------------------- #
CONCEPT_ANSWERS = {
    "random_forest": (
        "A Random Forest is an ensemble of decision trees. Each tree is trained on a random "
        "bootstrap sample of the traffic rows and, at every split, considers only a random subset "
        "of features. A single tree is fast but noisy; averaging 100 of them cancels much of that "
        "noise. For classification, every tree votes for a class and the majority wins — in "
        "AI-NIDS, 100 trees trained with n_estimators=100, random_state=42 vote across "
        "{classes} traffic classes, and the share of trees voting for the winning class becomes "
        "the reported confidence. Because the trees are independent, the same input always yields "
        "the same prediction, and scikit-learn can expose per-feature importances plus SHAP values, "
        "which is why this model was chosen for an explainable IDS."
    ),
    "risk_rules": (
        "Risk levels come from a documented formula, not from the model directly: "
        "risk_score = attack_severity_weight[predicted class] × confidence (+ 0.05 if the "
        "destination port is a sensitive service port). ≥0.90 is CRITICAL, ≥0.75 HIGH, ≥0.50 "
        "MEDIUM, otherwise LOW. Normal-traffic predictions are always LOW."
    ),
    "dos": (
        "Denial of Service (DoS) attacks attempt to exhaust network resources, CPU, memory, or connection "
        "tables on a target host to deny access to authorized users. In CICIDS2017 features, DoS manifests as "
        "abnormally elevated forward packet rates, short flow inter-arrival times, skewed forward/backward packet counts, "
        "and frequent connection resets."
    ),
    "ddos": (
        "Distributed Denial of Service (DDoS) multiplies DoS volume by orchestrating requests across distributed sources or "
        "botnets against a single destination endpoint. Flow features typically show sharp spikes in packet arrival rates, "
        "high aggregate flow bytes per second, and saturation of destination service ports."
    ),
    "port_scanning": (
        "Port Scanning is the systematic interrogation of target host ports to identify open services, protocol versions, "
        "and exploitable entry points. Model indicators typically include low packet counts per flow (1-3 SYN packets), "
        "short flow durations, low payload byte counts, and rapid sequential destination port probing."
    ),
    "brute_force": (
        "Brute Force attacks (such as SSH-Patator or FTP-Patator) systematically test password and credential combinations "
        "against authentication daemons. Observed traffic patterns demonstrate repetitive connections to ports 21 or 22, "
        "uniform flow duration distributions, and repeated handshake-and-termination sequences."
    ),
    "web_attack": (
        "Web Attacks encompass SQL Injection, Cross-Site Scripting (XSS), and web credential abuse against HTTP/HTTPS endpoints. "
        "Flows typically access ports 80, 443, or 8080, showing asymmetric payload lengths and elevated forward packet volumes "
        "corresponding to malicious request payloads."
    ),
    "bot": (
        "Bot traffic represents automated Command and Control (C2) communication or automated botnet coordination. Signatures "
        "feature regular beaconing intervals, repetitive small payload exchanges, and persistent connections to external hosts."
    ),
    "infiltration": (
        "Infiltration entails internal compromise where an adversary establishes a foothold within the perimeter and engages in "
        "internal network reconnaissance, lateral movement, or privilege escalation across internal subnets."
    ),
    "heartbleed": (
        "Heartbleed (CVE-2014-0160) exploits an OpenSSL TLS Heartbeat buffer over-read flaw on port 443. Attack flows typically "
        "feature small TLS forward request lengths that trigger disproportionately large response payloads leaking server memory."
    ),
    "normal": (
        "Normal Traffic represents standard, benign network communication conforming to RFC protocols, balanced forward and "
        "backward packet transfers, and typical client-server request-response timing."
    ),
    "out_of_scope": (
        "AI-NIDS is a defensive monitoring system: it classifies network-flow records that you "
        "upload. It does not scan, attack or modify any network, and it does not perform host "
        "exploitation or other offensive actions."
    ),
}

INTENT_KEYWORDS = {
    "explain_random_forest": ["random forest", "randomforest", "how does the model", "how does the ai work", "algorithm explain"],
    "risk_rules": ["risk level", "risk rule", "how is risk", "severity calculat"],
    "alerts": ["alert", "alarm", "notif"],
    "top_attack": ["most frequent attack", "most common attack", "which attack", "top attack", "appearing most"],
    "summary": ["summarize", "summarise", "summary", "overview of", "today's traffic", "todays traffic"],
    "model_info": ["accuracy", "model performance", "how accurate", "which model", "what model", "dataset"],
    "explain_dos": ["what is dos", "explain dos", "denial of service", "slowloris", "hulk", "goldeneye"],
    "explain_ddos": ["what is ddos", "explain ddos", "distributed denial"],
    "explain_port_scan": ["port scan", "portscan", "reconnaissance", "probing ports"],
    "explain_brute_force": ["brute force", "patator", "password attack", "credential attack"],
    "explain_web_attack": ["web attack", "sql injection", "sqli", "xss", "cross site scripting"],
    "explain_bot": ["botnet", "bot traffic", "c2", "command and control", "beaconing"],
    "explain_infiltration": ["infiltration", "lateral movement", "internal breach"],
    "explain_heartbleed": ["heartbleed", "cve-2014-0160"],
    "explain_normal": ["normal traffic", "benign traffic", "what is normal"],
    "network_state": ["network state", "network status", "threat level", "operational mode", "monitoring mode"],
    "system_health": ["system health", "health check", "is the system healthy", "system status", "backend health"],
    "config_explanation": ["detection config", "alert config", "configuration", "threshold setting", "sensitivity setting"],
    "audit_activity": ["audit log", "admin activity", "recent change", "who changed", "what changed", "admin action"],
    "investigation_summary": ["investigation", "incident", "active investigation", "summarize investigation"],
    "out_of_scope": ["hack", "exploit the", "attack a", "scan the network", "ddos the", "brute force the"],
}


def _has_data(db) -> bool:
    from sqlalchemy import func, select

    from app.models.database_models import Prediction

    return bool(db.scalar(select(func.count(Prediction.id))) or 0)


def _no_data() -> dict:
    return {
        "provider": "local",
        "answer": "There is currently no detection data available to analyze. Upload a traffic "
                  "dataset on the Traffic Analyzer page (or use the built-in sample) and run an "
                  "analysis first.",
        "facts": {},
        "sources": [],
    }


def answer(db, question: str, prediction_id: str | None = None, user: Any | None = None) -> dict:
    """Answer an assistant question using real dashboard/model data."""
    from sqlalchemy import func, select

    from app.models.database_models import Alert, Prediction
    from app.services import dashboard_service

    text = (question or "").strip().lower()
    intent = next(
        (name for name, keys in INTENT_KEYWORDS.items() if any(k in text for k in keys)), None
    )

    if intent == "out_of_scope":
        return {
            "provider": "local",
            "answer": CONCEPT_ANSWERS["out_of_scope"],
            "facts": {},
            "sources": [],
        }

    if intent == "explain_random_forest":
        classes = ", ".join(model_service.classes_) if model_service.is_loaded else "the trained classes"
        return {
            "provider": "local",
            "answer": CONCEPT_ANSWERS["random_forest"].format(classes=classes),
            "facts": {
                "algorithm": model_service.metadata.get("algorithm"),
                "n_estimators": model_service.metadata.get("n_estimators"),
                "n_features": len(model_service.feature_names()),
                "classes": model_service.classes_ if model_service.is_loaded else [],
            },
            "sources": ["model_metadata.json", "feature_columns.json"],
        }

    if intent == "risk_rules":
        from app.services import risk_service

        return {
            "provider": "local",
            "answer": CONCEPT_ANSWERS["risk_rules"],
            "facts": risk_service.rules_documentation(),
            "sources": ["risk_service.py (rule table)"],
        }

    if intent == "model_info":
        evaluation = model_service.evaluation
        return {
            "provider": "local",
            "answer": (
                f"The production model is a {model_service.metadata.get('algorithm')} "
                f"({model_service.metadata.get('n_estimators')} trees) trained on "
                f"{model_service.metadata.get('dataset')} with {len(model_service.feature_names())} "
                f"flow features across {model_service.metadata.get('n_classes')} traffic classes. "
                f"Reported accuracy is {evaluation.get('accuracy')} on the held-out "
                f"{evaluation.get('n_test'):,}-flow test split (random_state=42) — a 2017 research "
                "dataset, not a live-network guarantee."
                if evaluation.get("accuracy")
                else "The model metadata is available on the AI Model page."
            ),
            "facts": {
                "algorithm": model_service.metadata.get("algorithm"),
                "n_estimators": model_service.metadata.get("n_estimators"),
                "dataset": model_service.metadata.get("dataset"),
                "test_accuracy": evaluation.get("accuracy"),
                "n_test": evaluation.get("n_test"),
            },
            "sources": ["model_metadata.json", "evaluation.json"],
        }

    # Attack class concept explanations
    for key, concept_key in [
        ("explain_dos", "dos"),
        ("explain_ddos", "ddos"),
        ("explain_port_scan", "port_scanning"),
        ("explain_brute_force", "brute_force"),
        ("explain_web_attack", "web_attack"),
        ("explain_bot", "bot"),
        ("explain_infiltration", "infiltration"),
        ("explain_heartbleed", "heartbleed"),
        ("explain_normal", "normal"),
    ]:
        if intent == key:
            profile = class_profiles().get("profiles", {}).get(concept_key, {})
            return {
                "provider": "local",
                "answer": (
                    f"### Attack Class Explanation: {concept_key.replace('_', ' ').title()}\n\n"
                    f"**Summary**\n{CONCEPT_ANSWERS[concept_key]}\n\n"
                    f"**Observed Characteristics in Model**\n"
                    f"The Random Forest model was trained on CICIDS2017 flow statistics for this attack class. "
                    f"When scoring a packet flow, high deviation in packet arrival rates, flow duration, and "
                    f"sensitive port engagement push the model towards this classification.\n\n"
                    f"**Recommended Response**\n"
                    f"Open the related alert or flow in the Investigation Center to inspect the TreeSHAP contributions "
                    f"and verify host destination ports before recommending remediation actions."
                ),
                "facts": {"class": concept_key, "profile_available": bool(profile)},
                "sources": ["class_profiles.json", "cicids_config.py"],
            }

    # Operational state explanation
    if intent == "network_state":
        from app.services import network_status_service

        status_info = network_status_service.current_dict(db)
        return {
            "provider": "local",
            "answer": (
                f"### Operational Network State: {status_info.get('label', 'Normal').upper()}\n\n"
                f"**Summary**\n"
                f"The platform is currently operating in **{status_info.get('label')}** status "
                f"(source: {status_info.get('source', 'system')}).\n\n"
                f"**Details**\n"
                f"• Operational Status: `{status_info.get('status', 'normal')}`\n"
                f"• Threat Level: `{status_info.get('tone', 'normal').upper()}`\n"
                f"• Reason: {status_info.get('reason') or 'Standard operational baseline.'}\n"
                f"• Operational Mode: {status_info.get('description', '')}\n\n"
                f"**Why**\n"
                f"Status transitions are triggered either manually by an Admin in the Network Control Center "
                f"or automatically by threshold rules evaluating suspicious flow volume and active alerts."
            ),
            "facts": status_info,
            "sources": ["network_status table", "network_modes.py"],
        }

    # System health explanation
    if intent == "system_health":
        from app.api.health import _system_payload

        sys_data = _system_payload(db)
        model_ready = model_service.is_loaded
        return {
            "provider": "local",
            "answer": (
                f"### System Health Overview: {sys_data['status'].upper()}\n\n"
                f"**Status Checks**\n"
                f"• Database: {'Connected and operational' if sys_data['database']['ok'] else 'Error'}\n"
                f"• ML Model: {'Loaded (' + str(model_service.metadata.get('n_estimators', 100)) + ' trees)' if model_ready else 'Not loaded'}\n"
                f"• API Service: Operational\n"
                f"• Storage: {sys_data['uploads']['upload_files']} upload files ({round(sys_data['uploads']['upload_bytes'] / (1024*1024), 2)} MB)\n"
                f"• Uptime: {round(sys_data['uptime_seconds'] / 3600, 1)} hours"
            ),
            "facts": sys_data,
            "sources": ["health.py", "system_status"],
        }

    # Configuration explanation
    if intent == "config_explanation":
        from app.services import config_service

        runtime = config_service.runtime_snapshot(db)
        return {
            "provider": "local",
            "answer": (
                f"### Active Detection & Alert Configuration\n\n"
                f"• **Risk High Threshold**: {runtime.risk_high_threshold}\n"
                f"• **Risk Critical Threshold**: {runtime.risk_critical_threshold}\n"
                f"• **Alert Minimum Confidence**: {runtime.min_confidence_to_alert * 100:.0f}%\n"
                f"• **Max Alerts per Job**: {runtime.max_alerts_per_job} distinct pairs\n"
                f"• **Duplicate Alert Suppression**: {runtime.duplicate_handling.capitalize()}\n"
                f"• **Auto Incident Creation**: {'Enabled' if runtime.auto_incident_creation else 'Disabled'} "
                f"(severity >= {runtime.auto_incident_severity})"
            ),
            "facts": runtime.to_dict(),
            "sources": ["configuration_revisions", "config_service.py"],
        }

    # Admin audit activity
    if intent == "audit_activity":
        role = getattr(user, "role", None) if user else "analyst"
        if role != "admin":
            return {
                "provider": "local",
                "answer": (
                    "**Administrative Access Required**\n\n"
                    "Audit logs and administrator actions require Admin privileges. "
                    "As an Analyst, you can investigate traffic detections, model features, and alert queues."
                ),
                "facts": {"access_denied": True, "required_role": "admin"},
                "sources": ["RBAC policy (audit.view)"],
            }
        from app.models.database_models import AuditLog

        recent = db.scalars(select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(6)).all()
        log_items = [
            f"• **{log.action}** on `{log.resource}` ({log.result}) at {log.timestamp.strftime('%H:%M:%S UTC') if log.timestamp else 'recently'}"
            for log in recent
        ]
        return {
            "provider": "local",
            "answer": (
                f"### Recent Administrative Activity\n\n"
                + ("\n".join(log_items) if log_items else "No audit events recorded yet.")
            ),
            "facts": {"recent_logs": [log.to_dict() for log in recent]},
            "sources": ["audit_logs table"],
        }

    # Investigation summary
    if intent == "investigation_summary":
        from app.services import investigation_service

        inv_stats = investigation_service.investigation_stats(db)
        return {
            "provider": "local",
            "answer": (
                f"### Active Security Investigations Summary\n\n"
                f"• **Total Investigations**: {inv_stats.get('total', 0)}\n"
                f"• **Open / In Progress**: {inv_stats.get('open', 0) + inv_stats.get('in_progress', 0)}\n"
                f"• **Escalated**: {inv_stats.get('escalated', 0)}\n"
                f"• **Closed / Resolved**: {inv_stats.get('closed', 0)}\n\n"
                f"**Analyst Guidance**\n"
                f"Review high and critical severity incidents first. Check flow packet rates, duration, and "
                f"destination port indicators before taking response actions."
            ),
            "facts": inv_stats,
            "sources": ["investigations table", "investigation_service.py"],
        }

    # ---- data-dependent intents ---------------------------------------- #
    if not _has_data(db):
        return _no_data()

    if intent == "alerts":
        rows = db.execute(
            select(Alert.attack_type, Alert.severity, func.count())
            .group_by(Alert.attack_type, Alert.severity)
            .order_by(func.count().desc())
            .limit(10)
        ).all()
        open_alerts = int(
            db.scalar(select(func.count(Alert.id)).where(Alert.status != "resolved")) or 0
        )
        top = ", ".join(f"{attack} ({severity}, {count})" for attack, severity, count in rows) or "none"
        return {
            "provider": "local",
            "answer": (
                f"There are {open_alerts} unresolved alert(s) in the system. The most frequent "
                f"alert groups are: {top}. Alerts are raised only for attack predictions with "
                "MEDIUM risk or above; the highest-risk flows get individual alerts while the "
                "remainder are aggregated per attack type and destination port."
            ),
            "facts": {
                "unresolved_alerts": open_alerts,
                "groups": [
                    {"attack_type": a, "severity": s, "count": c} for a, s, c in rows
                ],
            },
            "sources": ["alerts table"],
        }

    if intent == "top_attack":
        rows = db.execute(
            select(Prediction.prediction, func.count())
            .where(Prediction.is_attack.is_(True))
            .group_by(Prediction.prediction)
            .order_by(func.count().desc())
            .limit(10)
        ).all()
        if not rows:
            return {
                "provider": "local",
                "answer": "No attack-classified traffic has been recorded yet, so there is no "
                          "attack type distribution to report.",
                "facts": {},
                "sources": ["predictions table"],
            }
        top_attack, top_count = rows[0][0], rows[0][1]
        total = sum(c for _, c in rows)
        share = 100 * top_count / total
        return {
            "provider": "local",
            "answer": (
                f"**{top_attack}** is the most frequently detected category: {top_count:,} flagged "
                f"flows, {share:.1f}% of all {total:,} suspicious flows recorded so far. Full "
                f"distribution: " + ", ".join(f"{a} {c:,}" for a, c in rows) + "."
            ),
            "facts": {"distribution": {a: c for a, c in rows}, "top_attack": top_attack},
            "sources": ["predictions table"],
        }

    if intent == "summary":
        stats = dashboard_service.overview(db, hours=24)
        summary = stats["metrics"]
        return {
            "provider": "local",
            "answer": (
                f"In the last 24 hours the system analysed {summary['total_traffic']:,} flows: "
                f"{summary['normal_traffic']:,} normal and {summary['suspicious_traffic']:,} "
                f"suspicious ({stats['verdict_share']['suspicious_pct']:.2f}% suspicious), with "
                f"{summary['active_alerts']:,} active alerts. The busiest attack category was "
                f"{max(stats['attack_distribution'], key=stats['attack_distribution'].get) if stats['attack_distribution'] else 'n/a'}. "
                f"Model test accuracy (CICIDS2017 held-out split) is "
                f"{(stats['model']['test_accuracy'] or 0) * 100:.2f}%."
            ),
            "facts": stats,
            "sources": ["detection_statistics + predictions + alerts tables"],
        }

    # ---- free-form: use the LLM when configured, else explain what we can do
    if settings.ai_enabled and prediction_id:
        from app.services.prediction_service import prediction_detail

        payload = prediction_detail(db, prediction_id, with_shap=True)
        if payload:
            evidence = build_prediction_evidence(payload, payload.get("explanation"), payload.get("ground_truth"))
            return explain(evidence)

    return {
        "provider": "local",
        "answer": (
            "I can answer questions that are grounded in this system's own data. Try:\n"
            "• “Why was this traffic classified as suspicious?” (open a flow first)\n"
            "• “Explain the current alerts.”\n"
            "• “What attack type is appearing most frequently?”\n"
            "• “Summarize today's detected traffic.”\n"
            "• “Explain Random Forest in simple terms.”\n"
            "• “How is the risk level calculated?”"
        ),
        "facts": {},
        "sources": [],
    }
