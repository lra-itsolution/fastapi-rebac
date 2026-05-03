from typing import Any

from sqlalchemy import Enum, ForeignKey, JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from ..db.base import Base, TimestampMixin, UUIDPKMixin
from ..enums import Action, AuditStatus as AuditStatusEnum
from ..types import JSONObject, TableKey, UserId


class AuditLog(Base, UUIDPKMixin, TimestampMixin):
    __tablename__ = "audit_log"

    actor_id: Mapped[UserId | None] = mapped_column(
        ForeignKey("user.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    action: Mapped[Action] = mapped_column(
        Enum(Action, name="rebac_action_enum", native_enum=False),
        nullable=False,
    )
    table_key: Mapped[TableKey | None] = mapped_column(String(255), nullable=True, index=True)
    object_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    status: Mapped[AuditStatusEnum] = mapped_column(
        Enum(AuditStatusEnum, name="rebac_audit_status_enum", native_enum=False),
        nullable=False,
    )
    client_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    request_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    meta: Mapped[JSONObject | dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    def __str__(self) -> str:
        return f"{self.action.value} {self.table_key or ''} {self.status.value}"
