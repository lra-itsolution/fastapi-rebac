from __future__ import annotations

from typing import Any, Sequence

from ..enums import SuspiciousSeverity
from ..types import JSONObject
from .config import SuspiciousActivityConfig
from .feature_builder import ActivityWindowFeatures, feature_vector_fields
from .rules import SuspiciousAlertCandidate


PYOD_ECOD_RULE_KEY = "pyod_ecod_outlier"


def _is_pyod_available() -> bool:
    try:
        import pyod  # noqa: F401
    except ImportError:
        return False
    return True


def is_pyod_available() -> bool:
    """Return whether PyOD is installed without making it a hard dependency."""

    return _is_pyod_available()


def _severity_from_rank(rank: int, total_outliers: int) -> SuspiciousSeverity:
    """Give a simple severity estimate based on an outlier score rank."""

    if total_outliers <= 1:
        return SuspiciousSeverity.MEDIUM
    if rank == 0:
        return SuspiciousSeverity.HIGH
    if rank <= max(1, total_outliers // 3):
        return SuspiciousSeverity.MEDIUM
    return SuspiciousSeverity.LOW


def _json_safe_feature_row(row: ActivityWindowFeatures) -> JSONObject:
    payload = row.to_payload()
    return payload


def detect_pyod_alerts(
    features: Sequence[ActivityWindowFeatures],
    *,
    config: SuspiciousActivityConfig | None = None,
) -> list[SuspiciousAlertCandidate]:
    """Detect statistical outliers in aggregated audit activity with PyOD ECOD.

    PyOD is deliberately optional. The library can be used with only the
    rule-based detector installed; if PyOD is missing or there is too little
    data, this function simply returns an empty list.
    """

    cfg = config or SuspiciousActivityConfig()
    if not cfg.enabled or not cfg.pyod_enabled:
        return []

    rows = [row for row in features if row.total_events > 0]
    if len(rows) < cfg.pyod_min_rows:
        return []

    total_events = sum(row.total_events for row in rows)
    if total_events < cfg.min_events_for_pyod:
        return []

    try:
        from pyod.models.ecod import ECOD
    except ImportError:
        return []

    vector_fields = feature_vector_fields()
    x = [row.to_vector() for row in rows]
    if not x:
        return []

    contamination = max(0.01, min(float(cfg.pyod_contamination), 0.49))
    model = ECOD(contamination=contamination)
    model.fit(x)

    labels = list(getattr(model, "labels_", []))
    scores = list(getattr(model, "decision_scores_", []))
    if len(labels) != len(rows) or len(scores) != len(rows):
        return []

    outlier_indices = [index for index, label in enumerate(labels) if int(label) == 1]
    if not outlier_indices:
        return []

    outlier_indices.sort(key=lambda index: float(scores[index]), reverse=True)
    candidates: list[SuspiciousAlertCandidate] = []

    for rank, index in enumerate(outlier_indices):
        row = rows[index]
        raw_score = float(scores[index])
        payload_details: dict[str, Any] = {
            "algorithm": "ECOD",
            "rule_key": PYOD_ECOD_RULE_KEY,
            "score": raw_score,
            "rank": rank + 1,
            "outliers_count": len(outlier_indices),
            "rows_count": len(rows),
            "total_events": total_events,
            "contamination": contamination,
            "feature_fields": list(vector_fields),
            "feature_vector": row.to_vector(),
            "note": (
                "PyOD marks this user/time-window as statistically unusual. "
                "This is not proof of an incident; it is a candidate for review."
            ),
        }
        candidates.append(
            SuspiciousAlertCandidate(
                actor_id=row.actor_id,
                detector_type="pyod",
                rule_key=PYOD_ECOD_RULE_KEY,
                severity=_severity_from_rank(rank, len(outlier_indices)),
                score=round(raw_score, 6),
                description=(
                    "PyOD ECOD detected statistically unusual user activity "
                    "during the analyzed window."
                ),
                window_start=row.window_start,
                window_end=row.window_end,
                audit_log_ids=list(row.audit_log_ids),
                payload={
                    "detector": "pyod",
                    "features": _json_safe_feature_row(row),
                    "details": payload_details,
                },
            )
        )

    return candidates


__all__ = [
    "PYOD_ECOD_RULE_KEY",
    "detect_pyod_alerts",
    "is_pyod_available",
]
