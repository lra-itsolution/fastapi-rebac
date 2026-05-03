from __future__ import annotations

from datetime import datetime
from uuid import UUID

from fastapi_users import schemas as fastapi_users_schemas
from pydantic import BaseModel, ConfigDict, Field

from .enums import Action, AuditStatus
from .types import JSONObject, ObjectId, TableKey


BaseUser = fastapi_users_schemas.BaseUser
BaseUserCreate = fastapi_users_schemas.BaseUserCreate
BaseUserUpdate = fastapi_users_schemas.BaseUserUpdate


class ReBACUserRead(BaseUser[UUID]):
    username: str

    first_name: str | None = None
    last_name: str | None = None

    is_staff: bool = False

    created_by_id: UUID | None = None
    supervisor_id: UUID | None = None

    created_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class ReBACUserCreate(BaseUserCreate):
    username: str = Field(min_length=3, max_length=150)

    first_name: str | None = Field(default=None, max_length=150)
    last_name: str | None = Field(default=None, max_length=150)


class ReBACUserUpdate(BaseUserUpdate):
    username: str | None = Field(default=None, min_length=3, max_length=150)

    first_name: str | None = Field(default=None, max_length=150)
    last_name: str | None = Field(default=None, max_length=150)


class ReBACAdminUserCreate(ReBACUserCreate):
    is_active: bool = True
    is_verified: bool = False
    is_superuser: bool = False
    is_staff: bool = False

    created_by_id: UUID | None = None
    supervisor_id: UUID | None = None


class ReBACAdminUserUpdate(ReBACUserUpdate):
    is_active: bool | None = None
    is_verified: bool | None = None
    is_superuser: bool | None = None
    is_staff: bool | None = None

    created_by_id: UUID | None = None
    supervisor_id: UUID | None = None


UserRead = ReBACUserRead
UserCreate = ReBACUserCreate
UserUpdate = ReBACUserUpdate
AdminUserCreate = ReBACAdminUserCreate
AdminUserUpdate = ReBACAdminUserUpdate


class GroupBase(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    share_members_visibility: bool = False
    share_creator_visibility: bool = False


class GroupRead(GroupBase):
    id: UUID
    created_by_id: UUID | None = None
    created_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class GroupCreate(GroupBase):
    pass


class GroupUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=150)
    share_members_visibility: bool | None = None
    share_creator_visibility: bool | None = None


class GroupMembershipRead(BaseModel):
    id: UUID
    group_id: UUID
    user_id: UUID

    model_config = ConfigDict(from_attributes=True)


class GroupMembershipCreate(BaseModel):
    group_id: UUID
    user_id: UUID


class AuthTableBase(BaseModel):
    key: TableKey = Field(min_length=1, max_length=255)
    title: str | None = Field(default=None, max_length=255)
    is_service: bool = False


class AuthTableRead(AuthTableBase):
    id: UUID

    model_config = ConfigDict(from_attributes=True)


class AuthTableCreate(AuthTableBase):
    pass


class AuthTableUpdate(BaseModel):
    title: str | None = Field(default=None, max_length=255)
    is_service: bool | None = None


class UserPermissionRead(BaseModel):
    id: UUID

    user_id: UUID
    table_id: UUID
    action: Action

    granted_by_id: UUID | None = None
    created_at: datetime | None = None

    model_config = ConfigDict(from_attributes=True)


class UserPermissionCreate(BaseModel):
    user_id: UUID
    table_id: UUID
    action: Action


class UserPermissionUpdate(BaseModel):
    action: Action | None = None


class GroupPermissionRead(BaseModel):
    id: UUID

    group_id: UUID
    table_id: UUID
    action: Action

    model_config = ConfigDict(from_attributes=True)


class GroupPermissionCreate(BaseModel):
    group_id: UUID
    table_id: UUID
    action: Action


class GroupPermissionUpdate(BaseModel):
    action: Action | None = None


class PermissionCheck(BaseModel):
    table_key: TableKey = Field(min_length=1, max_length=255)
    action: Action
    object_id: ObjectId | None = None


class PermissionCheckResult(BaseModel):
    allowed: bool
    table_key: TableKey
    action: Action
    object_id: ObjectId | None = None
    reason: str | None = None


class AuditLogRead(BaseModel):
    id: UUID

    created_at: datetime
    actor_id: UUID | None = None

    action: Action
    table_key: TableKey | None = None
    object_id: str | None = None

    status: AuditStatus

    client_ip: str | None = None
    user_agent: str | None = None
    request_id: str | None = None

    meta: JSONObject | None = None

    model_config = ConfigDict(from_attributes=True)


__all__ = [
    "BaseUser",
    "BaseUserCreate",
    "BaseUserUpdate",
    "ReBACUserRead",
    "ReBACUserCreate",
    "ReBACUserUpdate",
    "ReBACAdminUserCreate",
    "ReBACAdminUserUpdate",
    "UserRead",
    "UserCreate",
    "UserUpdate",
    "AdminUserCreate",
    "AdminUserUpdate",
    "GroupBase",
    "GroupRead",
    "GroupCreate",
    "GroupUpdate",
    "GroupMembershipRead",
    "GroupMembershipCreate",
    "AuthTableBase",
    "AuthTableRead",
    "AuthTableCreate",
    "AuthTableUpdate",
    "UserPermissionRead",
    "UserPermissionCreate",
    "UserPermissionUpdate",
    "GroupPermissionRead",
    "GroupPermissionCreate",
    "GroupPermissionUpdate",
    "PermissionCheck",
    "PermissionCheckResult",
    "AuditLogRead",
]
