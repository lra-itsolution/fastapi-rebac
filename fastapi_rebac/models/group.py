from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from ..db.base import Base, TimestampMixin, UUIDPKMixin
from ..types import UserId

if TYPE_CHECKING:
    from .group_membership import GroupMembership
    from .group_permission import GroupPermission


class Group(Base, UUIDPKMixin, TimestampMixin):

    __tablename__ = "group"

    name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    created_by_id: Mapped[UserId] = mapped_column(
        ForeignKey("user.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    share_members_visibility: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    share_creator_visibility: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    memberships: Mapped[list["GroupMembership"]] = relationship(
        "GroupMembership",
        back_populates="group",
        cascade="all, delete-orphan",
    )
    permissions: Mapped[list["GroupPermission"]] = relationship(
        "GroupPermission",
        back_populates="group",
        cascade="all, delete-orphan",
    )

    def __str__(self) -> str:
        return self.name
