from __future__ import annotations

from collections.abc import AsyncGenerator, Awaitable, Callable, Iterable, Mapping, Sequence
from typing import Any, Literal, Protocol, TypeAlias, TypeVar, TypedDict
from uuid import UUID

from fastapi_users.db import BaseUserDatabase
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import InstrumentedAttribute
from sqlalchemy.sql import Select

from .enums import Action


JSONPrimitive: TypeAlias = str | int | float | bool | None
JSONValue: TypeAlias = JSONPrimitive | list["JSONValue"] | dict[str, "JSONValue"]
JSONObject: TypeAlias = dict[str, JSONValue]

UUIDId: TypeAlias = UUID
PrimaryKeyId: TypeAlias = UUID
UserId: TypeAlias = UUID
GroupId: TypeAlias = UUID
AuthTableId: TypeAlias = UUID
PermissionId: TypeAlias = UUID
MembershipId: TypeAlias = UUID
AuditLogId: TypeAlias = UUID
SuspiciousAlertId: TypeAlias = UUID

TableKey: TypeAlias = str
BackendName: TypeAlias = str
ObjectId: TypeAlias = UUID | str | int
ActionName: TypeAlias = str

CRUDAction: TypeAlias = Literal[
    "CREATE",
    "READ",
    "UPDATE",
    "DELETE",
    "create",
    "read",
    "update",
    "delete",
]
ActionInput: TypeAlias = Action | ActionName | CRUDAction

PermissionStatus: TypeAlias = Literal["ALLOWED", "DENIED", "allowed", "denied"]
AuditStatus: TypeAlias = Literal["SUCCESS", "DENIED", "ERROR", "success", "denied", "error"]
CookieSameSite: TypeAlias = Literal["lax", "strict", "none"]

SessionDependency: TypeAlias = Callable[..., AsyncGenerator[AsyncSession, None]]
AsyncSessionFactory: TypeAlias = Callable[..., AsyncGenerator[AsyncSession, None]]
UserDatabaseDependency: TypeAlias = Callable[..., AsyncGenerator[BaseUserDatabase[Any, UserId], None]]
UserManagerDependency: TypeAlias = Callable[..., AsyncGenerator[Any, None]]
DependencyCallable: TypeAlias = Callable[..., Any]
CurrentUserDependency: TypeAlias = Callable[..., Any]
EnabledBackendsDependency: TypeAlias = Callable[..., Any]
CSRFProtectDependency: TypeAlias = Callable[..., Awaitable[None]]

ModelT = TypeVar("ModelT")
UserModelT = TypeVar("UserModelT", bound="SupportsReBACUser")
AdminUserModelT = TypeVar("AdminUserModelT", contravariant=True)
SchemaT = TypeVar("SchemaT")
ReturnT = TypeVar("ReturnT")

MaybeAwaitable: TypeAlias = ReturnT | Awaitable[ReturnT]

SelectStatement: TypeAlias = Select[tuple[Any, ...]]
Predicate: TypeAlias = Callable[..., bool]
AsyncPredicate: TypeAlias = Callable[..., Awaitable[bool]]

UserIdCollection: TypeAlias = Iterable[UserId] | Sequence[UserId] | set[UserId]
PermissionMap: TypeAlias = Mapping[TableKey, set[ActionName]]
UserRefAttribute: TypeAlias = InstrumentedAttribute[Any]
TableRef: TypeAlias = TableKey | type[Any] | UserRefAttribute


class SupportsReBACUser(Protocol):
    id: UserId
    email: str
    is_active: bool
    is_superuser: bool
    is_staff: bool

    created_by_id: UserId | None
    supervisor_id: UserId | None


class SupportsOwnedObject(Protocol):
    id: Any
    created_by_id: UserId | None


class SupportsUserObject(Protocol):
    id: Any
    user_id: UserId | None


class AdminUserManagerProtocol(Protocol[AdminUserModelT]):
    async def admin_prepare_create_dict(
        self,
        *,
        email: str,
        password: str,
        is_active: bool = True,
        is_superuser: bool = False,
        is_staff: bool = False,
        is_verified: bool = False,
        extra: JSONObject | dict[str, Any] | None = None,
    ) -> dict[str, Any]: ...

    async def admin_prepare_update_dict(
        self,
        user: AdminUserModelT,
        *,
        email: str | None = None,
        is_active: bool | None = None,
        is_superuser: bool | None = None,
        is_staff: bool | None = None,
        is_verified: bool | None = None,
        extra: JSONObject | dict[str, Any] | None = None,
    ) -> dict[str, Any]: ...

    async def admin_set_password(
        self,
        user: AdminUserModelT,
        *,
        password: str,
    ) -> str: ...


class AdminModelConfig(TypedDict):
    table_key: TableKey
    model: type[Any]
    title: str
    hidden: bool
    admin_view: str
    pk_attr_name: str
    user_ref_attr: UserRefAttribute | None
    form_exclude: set[str]
    readonly_fields: set[str]
    list_display: tuple[str, ...]
    allow_create: bool
    allow_update: bool
    allow_delete: bool


class AdminDisplayValue(TypedDict):
    label: str
    raw: Any
    url: str | None
    is_foreign_key: bool


class AdminFormChoice(TypedDict):
    value: str
    label: str
    url: str | None


class AdminFormField(TypedDict):
    name: str
    label: str
    required: bool
    readonly: bool
    input_type: str
    value: Any
    column: Any
    is_foreign_key: bool
    choices: list[AdminFormChoice]
    display: AdminDisplayValue


class AdminResourceRow(TypedDict):
    pk: Any
    cells: list[tuple[str, AdminDisplayValue]]


__all__ = [
    "JSONPrimitive",
    "JSONValue",
    "JSONObject",
    "UUIDId",
    "PrimaryKeyId",
    "UserId",
    "GroupId",
    "AuthTableId",
    "PermissionId",
    "MembershipId",
    "AuditLogId",
    "SuspiciousAlertId",
    "TableKey",
    "BackendName",
    "ObjectId",
    "ActionName",
    "CRUDAction",
    "ActionInput",
    "PermissionStatus",
    "AuditStatus",
    "CookieSameSite",
    "SessionDependency",
    "AsyncSessionFactory",
    "UserDatabaseDependency",
    "UserManagerDependency",
    "DependencyCallable",
    "CurrentUserDependency",
    "EnabledBackendsDependency",
    "CSRFProtectDependency",
    "ModelT",
    "UserModelT",
    "AdminUserModelT",
    "SchemaT",
    "ReturnT",
    "MaybeAwaitable",
    "SelectStatement",
    "Predicate",
    "AsyncPredicate",
    "UserIdCollection",
    "PermissionMap",
    "UserRefAttribute",
    "TableRef",
    "SupportsReBACUser",
    "SupportsOwnedObject",
    "SupportsUserObject",
    "AdminUserManagerProtocol",
    "AdminModelConfig",
    "AdminDisplayValue",
    "AdminFormChoice",
    "AdminFormField",
    "AdminResourceRow",
]