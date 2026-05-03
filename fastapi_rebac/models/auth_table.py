from typing import TYPE_CHECKING

from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..db.base import Base, TimestampMixin, UUIDPKMixin
from ..types import TableKey

if TYPE_CHECKING:
    from .group_permission import GroupPermission
    from .user_permission import UserPermission


class AuthTable(Base, UUIDPKMixin, TimestampMixin):

    __tablename__ = "auth_table"

    key: Mapped[TableKey] = mapped_column(String(255), unique=True, nullable=False, index=True)
    title: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_service: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    user_permissions: Mapped[list["UserPermission"]] = relationship(
        "UserPermission",
        back_populates="auth_table",
        cascade="all, delete-orphan",
    )
    group_permissions: Mapped[list["GroupPermission"]] = relationship(
        "GroupPermission",
        back_populates="auth_table",
        cascade="all, delete-orphan",
    )

    def __str__(self) -> str:
        return self.title or self.key
