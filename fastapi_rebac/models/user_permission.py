from typing import TYPE_CHECKING

from sqlalchemy import Enum, ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..db.base import Base, TimestampMixin, UUIDPKMixin
from ..enums import Action
from ..types import AuthTableId, UserId

if TYPE_CHECKING:
    from .auth_table import AuthTable


class UserPermission(Base, UUIDPKMixin, TimestampMixin):

    __tablename__ = "user_permission"
    __table_args__ = (
        UniqueConstraint("user_id", "table_id", "action", name="uq_user_permission"),
    )

    user_id: Mapped[UserId] = mapped_column(
        ForeignKey("user.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    table_id: Mapped[AuthTableId] = mapped_column(
        ForeignKey("auth_table.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    action: Mapped[Action] = mapped_column(
        Enum(Action, name="rebac_action_enum", native_enum=False),
        nullable=False,
    )
    granted_by_id: Mapped[UserId] = mapped_column(
        ForeignKey("user.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    auth_table: Mapped["AuthTable"] = relationship(
        "AuthTable",
        back_populates="user_permissions",
    )

    def __str__(self) -> str:
        return f"{self.action.value} on {self.table_id} for user {self.user_id}"
