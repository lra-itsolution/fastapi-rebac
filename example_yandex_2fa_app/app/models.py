from __future__ import annotations

from uuid import UUID

from fastapi_rebac.db.base import Base, TimestampMixin, UUIDPKMixin
from fastapi_rebac.models import User  # noqa: F401 - imports the default ReBAC user table
from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship


class Note(UUIDPKMixin, TimestampMixin, Base):
    """One simple business model protected by fastapi-rebac."""

    __tablename__ = "note"

    title: Mapped[str] = mapped_column(String(200), nullable=False)
    body: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by_id: Mapped[UUID] = mapped_column(
        ForeignKey("user.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_by: Mapped[User] = relationship(User)
