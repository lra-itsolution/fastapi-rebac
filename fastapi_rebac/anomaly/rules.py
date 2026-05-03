from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ..enums import SuspiciousSeverity
from ..types import JSONObject, UserId
from .config import SuspiciousActivityConfig
from .feature_builder import ActivityWindowFeatures


@dataclass(slots=True)
class SuspiciousAlertCandidate:
    """Detector output that can later be saved as SuspiciousAlert.

    The candidate is intentionally independent from SQLAlchemy so rule-based,
    PyOD and ADTK detectors can be tested without a database session.
    """

    actor_id: UserId | None
    detector_type: str
    rule_key: str
    severity: SuspiciousSeverity
    score: float | None
    description: str
    window_start: datetime
    window_end: datetime
    audit_log_ids: list[str]
    payload: JSONObject


def _ratio_score(value: int, threshold: int) -> float:
    if threshold <= 0:
        return 1.0
    return round(min(float(value) / float(threshold), 10.0), 4)


def _severity_by_ratio(value: int, threshold: int) -> SuspiciousSeverity:
    if threshold <= 0:
        return SuspiciousSeverity.LOW
    if value >= threshold * 3:
        return SuspiciousSeverity.HIGH
    if value >= threshold * 2:
        return SuspiciousSeverity.MEDIUM
    return SuspiciousSeverity.LOW


def _candidate(
    features: ActivityWindowFeatures,
    *,
    rule_key: str,
    severity: SuspiciousSeverity,
    score: float | None,
    description: str,
    payload: dict[str, Any],
) -> SuspiciousAlertCandidate:
    return SuspiciousAlertCandidate(
        actor_id=features.actor_id,
        detector_type="rule",
        rule_key=rule_key,
        severity=severity,
        score=score,
        description=description,
        window_start=features.window_start,
        window_end=features.window_end,
        audit_log_ids=list(features.audit_log_ids),
        payload={
            "rule_key": rule_key,
            "features": features.to_payload(),
            "details": payload,
        },
    )


def detect_rule_alerts(
    features: list[ActivityWindowFeatures],
    *,
    config: SuspiciousActivityConfig | None = None,
) -> list[SuspiciousAlertCandidate]:
    """Detect simple explainable suspicious activity patterns.

    These rules are the first MVP layer: they work even when there is not
    enough data for ML-based anomaly detection.
    """

    cfg = config or SuspiciousActivityConfig()
    if not cfg.enabled or not cfg.rules_enabled:
        return []

    alerts: list[SuspiciousAlertCandidate] = []
    for row in features:
        if row.total_events <= 0:
            continue

        if row.denied_count >= cfg.many_denied_threshold:
            alerts.append(
                _candidate(
                    row,
                    rule_key="many_denied",
                    severity=_severity_by_ratio(row.denied_count, cfg.many_denied_threshold),
                    score=_ratio_score(row.denied_count, cfg.many_denied_threshold),
                    description=(
                        f"User has {row.denied_count} denied actions "
                        f"during the analyzed window."
                    ),
                    payload={
                        "metric": "denied_count",
                        "value": row.denied_count,
                        "threshold": cfg.many_denied_threshold,
                    },
                )
            )

        if row.read_count >= cfg.bulk_read_threshold:
            alerts.append(
                _candidate(
                    row,
                    rule_key="bulk_read",
                    severity=_severity_by_ratio(row.read_count, cfg.bulk_read_threshold),
                    score=_ratio_score(row.read_count, cfg.bulk_read_threshold),
                    description=(
                        f"User has {row.read_count} read actions "
                        f"during the analyzed window."
                    ),
                    payload={
                        "metric": "read_count",
                        "value": row.read_count,
                        "threshold": cfg.bulk_read_threshold,
                    },
                )
            )

        if row.delete_count >= cfg.many_deletes_threshold:
            alerts.append(
                _candidate(
                    row,
                    rule_key="many_deletes",
                    severity=_severity_by_ratio(row.delete_count, cfg.many_deletes_threshold),
                    score=_ratio_score(row.delete_count, cfg.many_deletes_threshold),
                    description=(
                        f"User has {row.delete_count} delete actions "
                        f"during the analyzed window."
                    ),
                    payload={
                        "metric": "delete_count",
                        "value": row.delete_count,
                        "threshold": cfg.many_deletes_threshold,
                    },
                )
            )

        if row.unique_objects_count >= cfg.many_unique_objects_threshold:
            alerts.append(
                _candidate(
                    row,
                    rule_key="many_unique_objects",
                    severity=_severity_by_ratio(
                        row.unique_objects_count,
                        cfg.many_unique_objects_threshold,
                    ),
                    score=_ratio_score(row.unique_objects_count, cfg.many_unique_objects_threshold),
                    description=(
                        f"User touched {row.unique_objects_count} different objects "
                        f"during the analyzed window."
                    ),
                    payload={
                        "metric": "unique_objects_count",
                        "value": row.unique_objects_count,
                        "threshold": cfg.many_unique_objects_threshold,
                    },
                )
            )

        if row.unique_ips_count >= cfg.many_unique_ips_threshold:
            alerts.append(
                _candidate(
                    row,
                    rule_key="many_unique_ips",
                    severity=_severity_by_ratio(row.unique_ips_count, cfg.many_unique_ips_threshold),
                    score=_ratio_score(row.unique_ips_count, cfg.many_unique_ips_threshold),
                    description=(
                        f"User activity was observed from {row.unique_ips_count} "
                        f"different IP addresses during the analyzed window."
                    ),
                    payload={
                        "metric": "unique_ips_count",
                        "value": row.unique_ips_count,
                        "threshold": cfg.many_unique_ips_threshold,
                    },
                )
            )

        if row.night_administration_actions_count >= cfg.night_administration_actions_threshold:
            alerts.append(
                _candidate(
                    row,
                    rule_key="night_administration_action",
                    severity=SuspiciousSeverity.MEDIUM,
                    score=_ratio_score(
                        row.night_administration_actions_count,
                        cfg.night_administration_actions_threshold,
                    ),
                    description=(
                        f"User performed {row.night_administration_actions_count} "
                        f"administration actions at night."
                    ),
                    payload={
                        "metric": "night_administration_actions_count",
                        "value": row.night_administration_actions_count,
                        "threshold": cfg.night_administration_actions_threshold,
                        "night_start_hour": cfg.night_start_hour,
                        "night_end_hour": cfg.night_end_hour,
                    },
                )
            )

    return alerts
