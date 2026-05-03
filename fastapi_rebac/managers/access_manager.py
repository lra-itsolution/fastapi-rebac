from __future__ import annotations

import uuid
from collections.abc import Iterable
from typing import Any

from sqlalchemy import exists, false, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import ColumnProperty, RelationshipProperty

from ..enums import Action
from ..errors import ConfigurationError
from ..models import (
    AuthTable,
    Group,
    GroupMembership,
    GroupPermission,
    ReBACBaseUser,
    UserPermission,
)
from ..types import (
    ActionInput,
    AuthTableId,
    ObjectId,
    SelectStatement,
    TableKey,
    TableRef,
    UserId,
    UserIdCollection,
    UserRefAttribute,
)


class AccessManager:
    def __init__(
        self,
        session: AsyncSession,
        *,
        user_model: type[ReBACBaseUser],
        hidden_table_keys: set[TableKey] | None = None,
        group_model: type[Group] = Group,
        auth_table_model: type[AuthTable] = AuthTable,
        user_permission_model: type[UserPermission] = UserPermission,
        group_permission_model: type[GroupPermission] = GroupPermission,
        group_membership_model: type[GroupMembership] = GroupMembership,
    ) -> None:
        self.session = session
        self.user_model = user_model
        self.hidden_table_keys = set(hidden_table_keys or set())
        self.group_model = group_model
        self.auth_table_model = auth_table_model
        self.user_permission_model = user_permission_model
        self.group_permission_model = group_permission_model
        self.group_membership_model = group_membership_model

    async def can(
        self,
        *,
        user: ReBACBaseUser,
        action: ActionInput,
        table_key: TableRef,
    ) -> bool:
        normalized_action = self._normalize_action(action)
        resolved_table_key = self.resolve_table_key_from_ref(table_key)

        if not user.is_active:
            return False

        auth_table_id = await self._get_auth_table_id(resolved_table_key)
        if auth_table_id is None:
            return False

        if user.is_superuser:
            return True

        if await self._has_direct_permission(
            user_id=user.id,
            auth_table_id=auth_table_id,
            action=normalized_action,
        ):
            return True

        if await self._has_group_permission(
            user_id=user.id,
            auth_table_id=auth_table_id,
            action=normalized_action,
        ):
            return True

        return False

    async def can_any(
        self,
        *,
        user: ReBACBaseUser,
        action: ActionInput,
        table_keys: Iterable[TableRef],
    ) -> bool:
        for table_key in table_keys:
            if await self.can(user=user, action=action, table_key=table_key):
                return True
        return False

    async def can_all(
        self,
        *,
        user: ReBACBaseUser,
        action: ActionInput,
        table_keys: Iterable[TableRef],
    ) -> bool:
        for table_key in table_keys:
            if not await self.can(user=user, action=action, table_key=table_key):
                return False
        return True

    async def get_allowed_table_keys(
        self,
        *,
        user: ReBACBaseUser,
        action: ActionInput,
        exclude_hidden: bool = False,
    ) -> list[TableKey]:
        normalized_action = self._normalize_action(action)

        if not user.is_active:
            return []

        if user.is_superuser:
            stmt = select(self.auth_table_model.key).order_by(self.auth_table_model.key)
            result = await self.session.execute(stmt)
            items = list(result.scalars().all())
            if exclude_hidden:
                items = [item for item in items if item not in self.hidden_table_keys]
            return items

        direct_stmt = (
            select(self.auth_table_model.key)
            .join(
                self.user_permission_model,
                self.user_permission_model.table_id == self.auth_table_model.id,
            )
            .where(
                self.user_permission_model.user_id == user.id,
                self.user_permission_model.action == normalized_action,
            )
        )

        group_stmt = (
            select(self.auth_table_model.key)
            .join(
                self.group_permission_model,
                self.group_permission_model.table_id == self.auth_table_model.id,
            )
            .join(
                self.group_membership_model,
                self.group_membership_model.group_id == self.group_permission_model.group_id,
            )
            .where(
                self.group_membership_model.user_id == user.id,
                self.group_permission_model.action == normalized_action,
            )
        )

        direct_result = await self.session.execute(direct_stmt)
        group_result = await self.session.execute(group_stmt)

        keys = set(direct_result.scalars().all()) | set(group_result.scalars().all())
        items = sorted(keys)

        if exclude_hidden:
            items = [item for item in items if item not in self.hidden_table_keys]

        return items

    async def build_accessible_select(
        self,
        *,
        user: ReBACBaseUser,
        user_ref_attr: UserRefAttribute,
        action: ActionInput = Action.READ,
        check_table_permission: bool = True,
    ) -> SelectStatement:
        model = self.resolve_model(user_ref_attr)
        user_ref_column = self.resolve_user_ref_column(user_ref_attr)

        if check_table_permission:
            table_key = self.resolve_table_key(user_ref_attr)
            allowed = await self.can(user=user, action=action, table_key=table_key)
            if not allowed:
                return select(model).where(false())

        if not user.is_active:
            return select(model).where(false())

        if user.is_superuser:
            return select(model)

        visible_user_ids = await self._collect_visible_user_ids(user.id)
        if not visible_user_ids:
            return select(model).where(false())

        return select(model).where(user_ref_column.in_(visible_user_ids))

    async def get_accessible_object(
        self,
        *,
        user: ReBACBaseUser,
        user_ref_attr: UserRefAttribute,
        object_id: ObjectId,
        action: ActionInput = Action.READ,
        check_table_permission: bool = True,
    ) -> Any | None:
        model = self.resolve_model(user_ref_attr)
        id_column = self.resolve_object_id_column(model)
        try:
            coerced_object_id = self._coerce_value_for_column(id_column, object_id)
        except (TypeError, ValueError):
            return None

        stmt = await self.build_accessible_select(
            user=user,
            user_ref_attr=user_ref_attr,
            action=action,
            check_table_permission=check_table_permission,
        )
        stmt = stmt.where(id_column == coerced_object_id)

        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def can_object(
        self,
        *,
        user: ReBACBaseUser,
        action: ActionInput,
        user_ref_attr: UserRefAttribute,
        object_id: ObjectId,
    ) -> bool:
        obj = await self.get_accessible_object(
            user=user,
            user_ref_attr=user_ref_attr,
            object_id=object_id,
            action=action,
        )
        return obj is not None

    async def _collect_visible_user_ids(
        self,
        root_user_id: UserId,
        *,
        include_group_visibility_from_descendants: bool = False,
    ) -> set[UserId]:
        supervisor_hierarchy_ids = await self._get_hierarchy_user_ids(root_user_id)
        created_hierarchy_ids = await self._get_created_hierarchy_user_ids(root_user_id)
        hierarchy_user_ids = supervisor_hierarchy_ids | created_hierarchy_ids
        group_seed_user_ids = hierarchy_user_ids if include_group_visibility_from_descendants else {root_user_id}
        shared_user_ids = await self._get_group_visible_user_ids(group_seed_user_ids)
        return hierarchy_user_ids | shared_user_ids

    async def _get_hierarchy_user_ids(self, root_user_id: UserId) -> set[UserId]:
        return await self._get_recursive_user_ids(
            root_user_id,
            relation_column_name="supervisor_id",
            cte_name="rebac_visible_hierarchy",
        )

    async def _get_created_hierarchy_user_ids(self, root_user_id: UserId) -> set[UserId]:
        return await self._get_recursive_user_ids(
            root_user_id,
            relation_column_name="created_by_id",
            cte_name="rebac_created_hierarchy",
        )

    async def _get_recursive_user_ids(
        self,
        root_user_id: UserId,
        *,
        relation_column_name: str,
        cte_name: str,
    ) -> set[UserId]:
        user_table = self.user_model.__table__
        relation_column = getattr(user_table.c, relation_column_name, None)
        if relation_column is None:
            raise ConfigurationError(
                f"Could not resolve relation column {relation_column_name!r} on user model."
            )

        hierarchy_cte = (
            select(user_table.c.id)
            .where(user_table.c.id == root_user_id)
            .cte(name=cte_name, recursive=True)
        )

        user_alias = user_table.alias(f"{cte_name}_descendants")
        hierarchy_cte = hierarchy_cte.union(
            select(user_alias.c.id).where(
                getattr(user_alias.c, relation_column_name) == hierarchy_cte.c.id
            )
        )

        stmt = select(hierarchy_cte.c.id)
        result = await self.session.execute(stmt)
        return set(result.scalars().all())

    async def _get_group_visible_user_ids(
        self,
        seed_user_ids: UserIdCollection,
    ) -> set[UserId]:
        seed_ids = set(seed_user_ids)
        if not seed_ids:
            return set()

        group_ids_subquery = (
            select(self.group_membership_model.group_id)
            .where(self.group_membership_model.user_id.in_(seed_ids))
            .subquery()
        )

        members_stmt = (
            select(self.group_membership_model.user_id)
            .join(
                self.group_model,
                self.group_model.id == self.group_membership_model.group_id,
            )
            .where(
                self.group_membership_model.group_id.in_(
                    select(group_ids_subquery.c.group_id)
                ),
                self.group_model.share_members_visibility.is_(True),
            )
        )

        creators_stmt = (
            select(self.group_model.created_by_id)
            .where(
                self.group_model.id.in_(select(group_ids_subquery.c.group_id)),
                self.group_model.share_creator_visibility.is_(True),
                self.group_model.created_by_id.is_not(None),
            )
        )

        members_result = await self.session.execute(members_stmt)
        creators_result = await self.session.execute(creators_stmt)

        visible_user_ids = set(members_result.scalars().all())
        visible_user_ids.update(creators_result.scalars().all())
        visible_user_ids.discard(None)

        return visible_user_ids

    async def _get_auth_table_id(self, table_key: TableKey) -> AuthTableId | None:
        stmt = select(self.auth_table_model.id).where(self.auth_table_model.key == table_key)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def _has_direct_permission(
        self,
        *,
        user_id: UserId,
        auth_table_id: AuthTableId,
        action: Action,
    ) -> bool:
        stmt = select(
            exists().where(
                self.user_permission_model.user_id == user_id,
                self.user_permission_model.table_id == auth_table_id,
                self.user_permission_model.action == action,
            )
        )
        result = await self.session.execute(stmt)
        return bool(result.scalar())

    async def _has_group_permission(
        self,
        *,
        user_id: UserId,
        auth_table_id: AuthTableId,
        action: Action,
    ) -> bool:
        stmt = select(
            exists().where(
                self.group_membership_model.user_id == user_id,
                self.group_membership_model.group_id == self.group_permission_model.group_id,
                self.group_permission_model.table_id == auth_table_id,
                self.group_permission_model.action == action,
            )
        )
        result = await self.session.execute(stmt)
        return bool(result.scalar())

    @staticmethod
    def resolve_model(user_ref_attr: UserRefAttribute) -> type[Any]:
        model = getattr(user_ref_attr, "class_", None)
        if model is None:
            raise ConfigurationError("Could not resolve model from attribute.")
        return model

    @classmethod
    def resolve_table_key(cls, user_ref_attr: UserRefAttribute) -> TableKey:
        model = cls.resolve_model(user_ref_attr)
        return cls.resolve_table_key_from_model(model)

    @classmethod
    def resolve_table_key_from_ref(cls, table_ref: TableRef) -> TableKey:
        if isinstance(table_ref, str):
            return table_ref

        if hasattr(table_ref, "class_"):
            return cls.resolve_table_key(table_ref)

        if isinstance(table_ref, type):
            return cls.resolve_table_key_from_model(table_ref)

        raise ConfigurationError(
            "Table reference must be a table key string, SQLAlchemy model class, "
            "or SQLAlchemy mapped attribute."
        )

    @staticmethod
    def resolve_table_key_from_model(model: type[Any]) -> TableKey:
        table_key = getattr(model, "__tablename__", None)
        if not table_key:
            raise ConfigurationError(
                f"Could not resolve '__tablename__' for model {model!r}."
            )
        return str(table_key)

    @staticmethod
    def resolve_user_ref_column(user_ref_attr: UserRefAttribute) -> Any:
        prop = user_ref_attr.property

        if isinstance(prop, ColumnProperty):
            if len(prop.columns) != 1:
                raise ConfigurationError(
                    "User reference attribute must map to exactly one column."
                )
            return prop.columns[0]

        if isinstance(prop, RelationshipProperty):
            local_columns = list(prop.local_columns)
            if len(local_columns) != 1:
                raise ConfigurationError(
                    "User reference relationship must have exactly one local foreign key column."
                )
            return local_columns[0]

        raise ConfigurationError(
            "User reference attribute must be a mapped column or relationship."
        )

    @classmethod
    def resolve_object_id_column(cls, model: type[Any]) -> Any:
        try:
            id_attr = getattr(model, "id")
        except AttributeError as exc:
            raise ConfigurationError(
                f"Could not resolve object id column for model {model!r}."
            ) from exc

        return cls.resolve_user_ref_column(id_attr)

    @staticmethod
    def _coerce_value_for_column(column: Any, value: Any) -> Any:
        try:
            python_type = column.type.python_type
        except Exception:
            return value

        if value is None or isinstance(value, python_type):
            return value

        if python_type is uuid.UUID:
            return uuid.UUID(str(value))

        return python_type(value)

    @staticmethod
    def _normalize_action(action: ActionInput) -> Action:
        if isinstance(action, Action):
            return action

        raw = str(action).upper().strip()
        aliases = {
            "ADD": "CREATE",
            "CREATE": "CREATE",
            "READ": "READ",
            "GET": "READ",
            "UPDATE": "UPDATE",
            "EDIT": "UPDATE",
            "CHANGE": "UPDATE",
            "DELETE": "DELETE",
            "REMOVE": "DELETE",
        }
        normalized = aliases.get(raw, raw)

        by_name = getattr(Action, normalized, None)
        if by_name is not None:
            return by_name

        try:
            return Action(normalized)
        except Exception as exc:
            raise ConfigurationError(f"Unsupported action: {action!r}.") from exc
