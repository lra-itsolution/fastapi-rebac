from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Generic, TypeVar

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from .enums import Action
from .errors import ConfigurationError
from .managers.access_manager import AccessManager
from .models import ReBACBaseUser
from .types import ActionInput, DependencyCallable, ObjectId, SelectStatement, TableRef, UserRefAttribute

_UserT = TypeVar("_UserT", bound=ReBACBaseUser)

if TYPE_CHECKING:
    from .fastapi_rebac import FastAPIReBAC


class BaseAccessController(ABC, Generic[_UserT]):
    def __init__(self, rebac: "FastAPIReBAC[_UserT]") -> None:
        self.rebac = rebac

    @abstractmethod
    def require(self, action: ActionInput, table: TableRef) -> DependencyCallable:
        raise NotImplementedError

    @abstractmethod
    def accessible_select(self, user_ref_attr: UserRefAttribute) -> DependencyCallable:
        raise NotImplementedError

    @abstractmethod
    async def resolve_require(
        self,
        action: ActionInput,
        table: TableRef,
        *,
        user: _UserT | None = None,
        session: AsyncSession | None = None,
    ) -> _UserT:
        raise NotImplementedError

    @abstractmethod
    async def resolve_accessible_select(
        self,
        user_ref_attr: UserRefAttribute,
        *,
        user: _UserT | None = None,
        session: AsyncSession | None = None,
    ) -> SelectStatement:
        raise NotImplementedError

    @abstractmethod
    def require_object(
        self,
        action: ActionInput,
        user_ref_attr: UserRefAttribute,
        object_id: ObjectId | None = None,
        *,
        object_id_param: str = "id",
    ) -> DependencyCallable:
        raise NotImplementedError

    @abstractmethod
    async def resolve_require_object(
        self,
        action: ActionInput,
        user_ref_attr: UserRefAttribute,
        object_id: ObjectId,
        *,
        user: _UserT | None = None,
        session: AsyncSession | None = None,
    ) -> Any:
        raise NotImplementedError


class SQLAlchemyAccessController(BaseAccessController[_UserT], Generic[_UserT]):
    async def resolve_require(
        self,
        action: ActionInput,
        table: TableRef,
        *,
        user: _UserT | None = None,
        session: AsyncSession | None = None,
    ) -> _UserT:
        resolved_user = await self.rebac.resolve_user(user)
        resolved_session = await self.rebac.resolve_session(session)
        table_key = AccessManager.resolve_table_key_from_ref(table)
        access_manager = self.rebac.get_access_manager(resolved_session)

        allowed = await access_manager.can(
            user=resolved_user,
            action=action,
            table_key=table_key,
        )
        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not enough permissions.",
            )

        return resolved_user

    async def resolve_accessible_select(
        self,
        user_ref_attr: UserRefAttribute,
        *,
        user: _UserT | None = None,
        session: AsyncSession | None = None,
    ) -> SelectStatement:
        resolved_user = await self.resolve_require(
            Action.READ,
            user_ref_attr,
            user=user,
            session=session,
        )
        resolved_session = await self.rebac.resolve_session(session)
        access_manager = self.rebac.get_access_manager(resolved_session)

        return await access_manager.build_accessible_select(
            user=resolved_user,
            user_ref_attr=user_ref_attr,
            check_table_permission=False,
        )

    async def resolve_require_object(
        self,
        action: ActionInput,
        user_ref_attr: UserRefAttribute,
        object_id: ObjectId,
        *,
        user: _UserT | None = None,
        session: AsyncSession | None = None,
    ) -> Any:
        resolved_user = await self.resolve_require(
            action,
            user_ref_attr,
            user=user,
            session=session,
        )
        resolved_session = await self.rebac.resolve_session(session)
        access_manager = self.rebac.get_access_manager(resolved_session)

        obj = await access_manager.get_accessible_object(
            user=resolved_user,
            user_ref_attr=user_ref_attr,
            object_id=object_id,
            action=action,
            check_table_permission=False,
        )
        if obj is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Object not found.",
            )

        return obj

    def require(self, action: ActionInput, table: TableRef) -> DependencyCallable:
        session_dependency = self.rebac.session_dependency

        async def dependency(
            user: _UserT = Depends(self.rebac.auth_required),
            session: AsyncSession = Depends(session_dependency),
        ) -> _UserT:
            return await self.resolve_require(
                action,
                table,
                user=user,
                session=session,
            )

        return dependency

    def accessible_select(self, user_ref_attr: UserRefAttribute) -> DependencyCallable:
        session_dependency = self.rebac.session_dependency

        async def dependency(
            user: _UserT = Depends(self.rebac.auth_required),
            session: AsyncSession = Depends(session_dependency),
        ) -> SelectStatement:
            return await self.resolve_accessible_select(
                user_ref_attr,
                user=user,
                session=session,
            )

        return dependency

    def require_object(
        self,
        action: ActionInput,
        user_ref_attr: UserRefAttribute,
        object_id: ObjectId | None = None,
        *,
        object_id_param: str = "id",
    ) -> DependencyCallable:
        session_dependency = self.rebac.session_dependency

        if object_id is not None:
            async def dependency_with_explicit_object_id(
                user: _UserT = Depends(self.rebac.auth_required),
                session: AsyncSession = Depends(session_dependency),
            ) -> Any:
                return await self.resolve_require_object(
                    action,
                    user_ref_attr,
                    object_id,
                    user=user,
                    session=session,
                )

            return dependency_with_explicit_object_id

        async def dependency_from_path(
            request: Request,
            user: _UserT = Depends(self.rebac.auth_required),
            session: AsyncSession = Depends(session_dependency),
        ) -> Any:
            try:
                raw_object_id = request.path_params[object_id_param]
            except KeyError as exc:
                raise ConfigurationError(
                    f"Path parameter {object_id_param!r} was not found."
                ) from exc

            return await self.resolve_require_object(
                action,
                user_ref_attr,
                raw_object_id,
                user=user,
                session=session,
            )

        return dependency_from_path
