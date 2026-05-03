from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Enum, Float, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..db.base import Base, TimestampMixin, UUIDPKMixin
from ..enums import SuspiciousSeverity, SuspiciousStatus
from ..types import JSONObject, UserId


class SuspiciousAlert(Base, UUIDPKMixin, TimestampMixin):
    """Detected suspicious activity stored separately from immutable audit facts.

    AuditLog remains the source of raw events. This table stores analysis
    results produced by rules, PyOD, ADTK or any future detector.
    """

    __tablename__ = "suspicious_alert"

    actor_id: Mapped[UserId | None] = mapped_column(
        ForeignKey("user.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    detector_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    rule_key: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    severity: Mapped[SuspiciousSeverity] = mapped_column(
        Enum(
            SuspiciousSeverity,
            name="rebac_suspicious_severity_enum",
            native_enum=False,
        ),
        default=SuspiciousSeverity.LOW,
        nullable=False,
        index=True,
    )
    score: Mapped[float | None] = mapped_column(Float, nullable=True)
    status: Mapped[SuspiciousStatus] = mapped_column(
        Enum(
            SuspiciousStatus,
            name="rebac_suspicious_status_enum",
            native_enum=False,
        ),
        default=SuspiciousStatus.NEW,
        nullable=False,
        index=True,
    )
    description: Mapped[str] = mapped_column(Text, nullable=False)
    window_start: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )
    window_end: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True),
        nullable=True,
        index=True,
    )
    audit_log_ids: Mapped[list[str] | None] = mapped_column(JSON, nullable=True)
    payload: Mapped[JSONObject | dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    def __str__(self) -> str:
        return f"{self.severity.value} {self.detector_type}:{self.rule_key}"
