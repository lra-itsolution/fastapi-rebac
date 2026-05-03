from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import TYPE_CHECKING, TypeVar, cast

from fastapi import Depends
from fastapi_users.db import SQLAlchemyUserDatabase
from sqlalchemy.ext.asyncio import AsyncSession

from ..types import SessionDependency, UserDatabaseDependency, UserId

if TYPE_CHECKING:
    from fastapi_users.db import BaseUserDatabase

    from ..managers.user_manager import ReBACUserManager
    from ..models.user import ReBACBaseUser

_UserT = TypeVar("_UserT", bound="ReBACBaseUser")


def create_sqlalchemy_user_db(
    session: AsyncSession,
    user_model: type[_UserT],
) -> SQLAlchemyUserDatabase[_UserT, UserId]:
    return SQLAlchemyUserDatabase(session, user_model)


def build_get_user_db(
    user_model: type[_UserT],
    get_async_session: SessionDependency,
) -> UserDatabaseDependency:
    async def get_user_db(
        session: AsyncSession = Depends(get_async_session),
    ) -> AsyncGenerator[SQLAlchemyUserDatabase[_UserT, UserId], None]:
        yield create_sqlalchemy_user_db(session, user_model)

    return get_user_db


def create_user_manager(
    manager_class: type[ReBACUserManager[_UserT]],
    user_db: BaseUserDatabase[_UserT, UserId],
) -> ReBACUserManager[_UserT]:
    return cast("ReBACUserManager[_UserT]", cast(object, manager_class(user_db)))


__all__ = [
    "build_get_user_db",
    "create_sqlalchemy_user_db",
    "create_user_manager",
]
