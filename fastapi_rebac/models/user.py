from typing import TYPE_CHECKING, Any

from fastapi_users.db import SQLAlchemyBaseUserTableUUID
from sqlalchemy import Boolean, ForeignKey, String
from sqlalchemy.orm import Mapped, declared_attr, foreign, mapped_column, relationship

from ..db.base import Base, TimestampMixin
from ..types import UserId

if TYPE_CHECKING:
    from .audit_log import AuditLog
    from .group import Group
    from .group_membership import GroupMembership
    from .user_permission import UserPermission


class ReBACBaseUser(SQLAlchemyBaseUserTableUUID, Base, TimestampMixin):

    __abstract__ = True

    username: Mapped[str] = mapped_column(
        String(150),
        unique=True,
        index=True,
        nullable=False,
    )
    first_name: Mapped[str | None] = mapped_column(String(150), nullable=True)
    last_name: Mapped[str | None] = mapped_column(String(150), nullable=True)
    is_staff: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    @declared_attr
    def created_by_id(cls) -> Mapped[UserId | None]:
        return mapped_column(
            ForeignKey(f"{cls.__tablename__}.id", ondelete="SET NULL"),
            nullable=True,
            index=True,
        )

    @declared_attr
    def supervisor_id(cls) -> Mapped[UserId | None]:
        return mapped_column(
            ForeignKey(f"{cls.__tablename__}.id", ondelete="SET NULL"),
            nullable=True,
            index=True,
        )

    @declared_attr
    def created_by(cls) -> Mapped[Any]:
        return relationship(
            cls,
            remote_side=lambda: [cls.id],
            foreign_keys=lambda: [cls.created_by_id],
            back_populates="created_users",
        )

    @declared_attr
    def created_users(cls) -> Mapped[list[Any]]:
        return relationship(
            cls,
            foreign_keys=lambda: [cls.created_by_id],
            back_populates="created_by",
        )

    @declared_attr
    def supervisor(cls) -> Mapped[Any]:
        return relationship(
            cls,
            remote_side=lambda: [cls.id],
            foreign_keys=lambda: [cls.supervisor_id],
            back_populates="subordinates",
        )

    @declared_attr
    def subordinates(cls) -> Mapped[list[Any]]:
        return relationship(
            cls,
            foreign_keys=lambda: [cls.supervisor_id],
            back_populates="supervisor",
        )

    @declared_attr
    def group_memberships(cls) -> Mapped[list["GroupMembership"]]:
        from .group_membership import GroupMembership

        return relationship(
            GroupMembership,
            primaryjoin=lambda: foreign(GroupMembership.user_id) == cls.id,
            cascade="all, delete-orphan",
        )

    @declared_attr
    def user_permissions(cls) -> Mapped[list["UserPermission"]]:
        from .user_permission import UserPermission

        return relationship(
            UserPermission,
            primaryjoin=lambda: foreign(UserPermission.user_id) == cls.id,
            cascade="all, delete-orphan",
        )

    @declared_attr
    def granted_permissions(cls) -> Mapped[list["UserPermission"]]:
        from .user_permission import UserPermission

        return relationship(
            UserPermission,
            primaryjoin=lambda: foreign(UserPermission.granted_by_id) == cls.id,
        )

    @declared_attr
    def created_groups(cls) -> Mapped[list["Group"]]:
        from .group import Group

        return relationship(
            Group,
            primaryjoin=lambda: foreign(Group.created_by_id) == cls.id,
        )

    @declared_attr
    def audit_logs(cls) -> Mapped[list["AuditLog"]]:
        from .audit_log import AuditLog

        return relationship(
            AuditLog,
            primaryjoin=lambda: foreign(AuditLog.actor_id) == cls.id,
        )

    def __str__(self) -> str:
        username = getattr(self, "username", None)
        email = getattr(self, "email", None)
        if username and email:
            return f"{username} ({email})"
        return str(email or username or getattr(self, "id", ""))


class User(ReBACBaseUser):
    __tablename__ = "user"
