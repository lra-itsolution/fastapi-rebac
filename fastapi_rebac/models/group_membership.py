from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..db.base import Base, TimestampMixin, UUIDPKMixin
from ..types import GroupId, UserId

if TYPE_CHECKING:
    from .group import Group


class GroupMembership(Base, UUIDPKMixin, TimestampMixin):

    __tablename__ = "group_membership"
    __table_args__ = (
        UniqueConstraint("group_id", "user_id", name="uq_group_membership_group_user"),
    )

    group_id: Mapped[GroupId] = mapped_column(
        ForeignKey("group.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    user_id: Mapped[UserId] = mapped_column(
        ForeignKey("user.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_by_id: Mapped[UserId] = mapped_column(
        ForeignKey("user.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    group: Mapped["Group"] = relationship("Group", back_populates="memberships")

    def __str__(self) -> str:
        return f"{self.user_id} in {self.group_id} created by {self.created_by_id}"
