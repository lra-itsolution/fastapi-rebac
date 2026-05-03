from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column

from ...db.base import Base, TimestampMixin, UUIDPKMixin
from ...types import UserId


class YandexSecondFactor(UUIDPKMixin, TimestampMixin, Base):
    """Binding between a local user and a Yandex ID account."""

    __tablename__ = "rebac_yandex_second_factor"

    user_id: Mapped[UserId] = mapped_column(
        ForeignKey("user.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        unique=True,
    )
    provider_subject: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    yandex_login: Mapped[str | None] = mapped_column(String(255), nullable=True)
    yandex_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    yandex_psuid: Mapped[str | None] = mapped_column(String(512), nullable=True)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    __table_args__ = (
        Index("ix_rebac_yandex_second_factor_user_enabled", "user_id", "is_enabled"),
    )


class YandexPreAuthSession(UUIDPKMixin, Base):
    """Temporary state created after password auth and before Yandex confirmation."""

    __tablename__ = "rebac_yandex_pre_auth_session"

    user_id: Mapped[UserId] = mapped_column(
        ForeignKey("user.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    state: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    purpose: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    code_verifier: Mapped[str | None] = mapped_column(String(255), nullable=True)
    redirect_after: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (
        UniqueConstraint("state", name="uq_rebac_yandex_pre_auth_state"),
        Index("ix_rebac_yandex_pre_auth_user_purpose", "user_id", "purpose"),
    )
