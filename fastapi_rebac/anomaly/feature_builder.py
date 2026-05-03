from __future__ import annotations

from collections import defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..enums import Action, AuditStatus
from ..models.audit_log import AuditLog
from ..types import JSONObject, UserId

DEFAULT_ADMINISTRATION_TABLE_KEYS: frozenset[str] = frozenset(
    {
        "user",
        "group",
        "auth_table",
        "audit_log",
        "suspicious_alert",
        "group_membership",
        "group_permission",
        "user_permission",
    }
)

FEATURE_VECTOR_FIELDS: tuple[str, ...] = (
    "total_events",
    "success_count",
    "denied_count",
    "error_count",
    "create_count",
    "read_count",
    "update_count",
    "delete_count",
    "unique_objects_count",
    "unique_tables_count",
    "unique_ips_count",
    "night_actions_count",
    "administration_actions_count",
    "night_administration_actions_count",
)


@dataclass(slots=True)
class ActivityWindowFeatures:
    """Aggregated user activity features for one time window.

    This object is intentionally plain and numeric-friendly: rule-based
    detectors and PyOD can use the same feature rows without depending on
    SQLAlchemy models directly.
    """

    actor_id: UserId | None
    window_start: datetime
    window_end: datetime
    audit_log_ids: list[str]

    total_events: int = 0
    success_count: int = 0
    denied_count: int = 0
    error_count: int = 0

    create_count: int = 0
    read_count: int = 0
    update_count: int = 0
    delete_count: int = 0

    unique_objects_count: int = 0
    unique_tables_count: int = 0
    unique_ips_count: int = 0
    night_actions_count: int = 0
    administration_actions_count: int = 0
    night_administration_actions_count: int = 0

    def to_vector(self) -> list[float]:
        """Return a stable numeric vector for PyOD-like detectors."""

        return [float(getattr(self, field_name)) for field_name in FEATURE_VECTOR_FIELDS]

    def to_payload(self) -> JSONObject:
        """Return JSON-serializable diagnostic data for SuspiciousAlert.payload."""

        data = asdict(self)
        data["actor_id"] = str(self.actor_id) if self.actor_id is not None else None
        data["window_start"] = self.window_start.isoformat()
        data["window_end"] = self.window_end.isoformat()
        return data  # type: ignore[return-value]


def feature_vector_fields() -> tuple[str, ...]:
    """Expose vector order so detectors can explain their inputs."""

    return FEATURE_VECTOR_FIELDS


def _enum_value(value: Any) -> str | None:
    if value is None:
        return None
    return str(getattr(value, "value", value)).upper()


def _is_night_time(
    moment: datetime,
    *,
    night_start_hour: int,
    night_end_hour: int,
) -> bool:
    hour = moment.hour
    if night_start_hour == night_end_hour:
        return False
    if night_start_hour < night_end_hour:
        return night_start_hour <= hour < night_end_hour
    return hour >= night_start_hour or hour < night_end_hour


def build_activity_window_features(
    audit_logs: Iterable[AuditLog],
    *,
    window_start: datetime,
    window_end: datetime,
    night_start_hour: int = 22,
    night_end_hour: int = 6,
    administration_table_keys: Sequence[str] | set[str] | frozenset[str] | None = None,
) -> list[ActivityWindowFeatures]:
    """Build per-user activity features from AuditLog rows.

    The function does not mutate AuditLog and does not create alerts. It only
    converts raw audit facts into compact numeric rows for later detectors.
    """

    admin_keys = set(administration_table_keys or DEFAULT_ADMINISTRATION_TABLE_KEYS)
    grouped: dict[UserId | None, dict[str, Any]] = defaultdict(
        lambda: {
            "audit_log_ids": [],
            "objects": set(),
            "tables": set(),
            "ips": set(),
            "total_events": 0,
            "success_count": 0,
            "denied_count": 0,
            "error_count": 0,
            "create_count": 0,
            "read_count": 0,
            "update_count": 0,
            "delete_count": 0,
            "night_actions_count": 0,
            "administration_actions_count": 0,
            "night_administration_actions_count": 0,
        }
    )

    for log in audit_logs:
        bucket = grouped[getattr(log, "actor_id", None)]
        bucket["total_events"] += 1
        bucket["audit_log_ids"].append(str(log.id))

        action = _enum_value(getattr(log, "action", None))
        status = _enum_value(getattr(log, "status", None))
        table_key = getattr(log, "table_key", None)
        object_id = getattr(log, "object_id", None)
        client_ip = getattr(log, "client_ip", None)
        created_at = getattr(log, "created_at", None)

        if status == AuditStatus.SUCCESS.value:
            bucket["success_count"] += 1
        elif status == AuditStatus.DENIED.value:
            bucket["denied_count"] += 1
        elif status == AuditStatus.ERROR.value:
            bucket["error_count"] += 1

        if action == Action.CREATE.value:
            bucket["create_count"] += 1
        elif action == Action.READ.value:
            bucket["read_count"] += 1
        elif action == Action.UPDATE.value:
            bucket["update_count"] += 1
        elif action == Action.DELETE.value:
            bucket["delete_count"] += 1

        is_admin_action = False
        if table_key:
            bucket["tables"].add(str(table_key))
            if str(table_key) in admin_keys:
                bucket["administration_actions_count"] += 1
                is_admin_action = True
        if object_id:
            bucket["objects"].add(str(object_id))
        if client_ip:
            bucket["ips"].add(str(client_ip))
        is_night_action = isinstance(created_at, datetime) and _is_night_time(
            created_at,
            night_start_hour=night_start_hour,
            night_end_hour=night_end_hour,
        )
        if is_night_action:
            bucket["night_actions_count"] += 1
            if is_admin_action:
                bucket["night_administration_actions_count"] += 1

    result: list[ActivityWindowFeatures] = []
    for actor_id, bucket in grouped.items():
        result.append(
            ActivityWindowFeatures(
                actor_id=actor_id,
                window_start=window_start,
                window_end=window_end,
                audit_log_ids=bucket["audit_log_ids"],
                total_events=bucket["total_events"],
                success_count=bucket["success_count"],
                denied_count=bucket["denied_count"],
                error_count=bucket["error_count"],
                create_count=bucket["create_count"],
                read_count=bucket["read_count"],
                update_count=bucket["update_count"],
                delete_count=bucket["delete_count"],
                unique_objects_count=len(bucket["objects"]),
                unique_tables_count=len(bucket["tables"]),
                unique_ips_count=len(bucket["ips"]),
                night_actions_count=bucket["night_actions_count"],
                administration_actions_count=bucket["administration_actions_count"],
                night_administration_actions_count=bucket["night_administration_actions_count"],
            )
        )

    return result


async def load_activity_window_features(
    session: AsyncSession,
    *,
    window_start: datetime | None = None,
    window_end: datetime | None = None,
    window_minutes: int = 60,
    night_start_hour: int = 22,
    night_end_hour: int = 6,
    administration_table_keys: Sequence[str] | set[str] | frozenset[str] | None = None,
) -> list[ActivityWindowFeatures]:
    """Load AuditLog rows for a window and aggregate them into feature rows."""

    if window_end is None:
        window_end = datetime.now(timezone.utc)
    if window_start is None:
        window_start = window_end - timedelta(minutes=window_minutes)

    stmt = (
        select(AuditLog)
        .where(AuditLog.created_at >= window_start)
        .where(AuditLog.created_at < window_end)
        .order_by(AuditLog.created_at)
    )
    rows = list((await session.execute(stmt)).scalars().all())
    return build_activity_window_features(
        rows,
        window_start=window_start,
        window_end=window_end,
        night_start_hour=night_start_hour,
        night_end_hour=night_end_hour,
        administration_table_keys=administration_table_keys,
    )
