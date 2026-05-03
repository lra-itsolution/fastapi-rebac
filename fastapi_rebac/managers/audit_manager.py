from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from ..enums import Action, AuditStatus
from ..models.audit_log import AuditLog
from ..models.user import ReBACBaseUser
from ..types import JSONObject, ObjectId, TableKey, UserId


DEFAULT_AUDIT_ACTIONS: frozenset[Action] = frozenset(
    {
        Action.CREATE,
        Action.UPDATE,
        Action.DELETE,
    }
)


def normalize_audit_actions(actions: Iterable[Action | str] | None) -> frozenset[Action]:
    if actions is None:
        return DEFAULT_AUDIT_ACTIONS

    normalized: set[Action] = set()
    for action in actions:
        if isinstance(action, Action):
            normalized.add(action)
            continue

        action_value = action.strip()
        try:
            normalized.add(Action(action_value))
            continue
        except ValueError:
            action_by_name = Action.__members__.get(action_value)
            if action_by_name is not None:
                normalized.add(action_by_name)
                continue

        raise ValueError(f"Unknown audit action: {action!r}.")

    return frozenset(normalized)


class AuditManager:
    def __init__(
        self,
        session: AsyncSession,
        *,
        enabled: bool = True,
        actions: Iterable[Action | str] | None = None,
    ) -> None:
        self.session = session
        self.enabled = enabled
        self.actions = normalize_audit_actions(actions)

    def should_log(self, action: Action | str) -> bool:
        if not self.enabled:
            return False
        return self._normalize_action(action) in self.actions

    async def log(
        self,
        *,
        action: Action | str,
        status: AuditStatus | str,
        actor: ReBACBaseUser | UserId | None = None,
        table_key: TableKey | None = None,
        object_id: ObjectId | None = None,
        request: Request | None = None,
        meta: JSONObject | Mapping[str, Any] | None = None,
        commit: bool = True,
    ) -> AuditLog | None:
        action_enum = self._normalize_action(action)
        if not self.should_log(action_enum):
            return None

        status_enum = self._normalize_status(status)
        actor_id = self._resolve_actor_id(actor)
        client_ip = request.client.host if request is not None and request.client is not None else None
        user_agent = request.headers.get("user-agent") if request is not None else None
        request_id = request.headers.get("x-request-id") if request is not None else None

        entry = AuditLog(
            actor_id=actor_id,
            action=action_enum,
            table_key=table_key,
            object_id=str(object_id) if object_id is not None else None,
            status=status_enum,
            client_ip=client_ip,
            user_agent=user_agent,
            request_id=request_id,
            meta=dict(meta) if meta is not None else None,
        )
        self.session.add(entry)

        if commit:
            await self.session.commit()
        else:
            await self.session.flush()

        return entry

    async def log_success(
        self,
        *,
        action: Action | str,
        actor: ReBACBaseUser | UserId | None = None,
        table_key: TableKey | None = None,
        object_id: ObjectId | None = None,
        request: Request | None = None,
        meta: JSONObject | Mapping[str, Any] | None = None,
        commit: bool = True,
    ) -> AuditLog | None:
        return await self.log(
            action=action,
            status=AuditStatus.SUCCESS,
            actor=actor,
            table_key=table_key,
            object_id=object_id,
            request=request,
            meta=meta,
            commit=commit,
        )

    async def log_denied(
        self,
        *,
        action: Action | str,
        actor: ReBACBaseUser | UserId | None = None,
        table_key: TableKey | None = None,
        object_id: ObjectId | None = None,
        request: Request | None = None,
        meta: JSONObject | Mapping[str, Any] | None = None,
        commit: bool = True,
    ) -> AuditLog | None:
        return await self.log(
            action=action,
            status=AuditStatus.DENIED,
            actor=actor,
            table_key=table_key,
            object_id=object_id,
            request=request,
            meta=meta,
            commit=commit,
        )

    async def log_error(
        self,
        *,
        action: Action | str,
        actor: ReBACBaseUser | UserId | None = None,
        table_key: TableKey | None = None,
        object_id: ObjectId | None = None,
        request: Request | None = None,
        meta: JSONObject | Mapping[str, Any] | None = None,
        commit: bool = True,
    ) -> AuditLog | None:
        return await self.log(
            action=action,
            status=AuditStatus.ERROR,
            actor=actor,
            table_key=table_key,
            object_id=object_id,
            request=request,
            meta=meta,
            commit=commit,
        )

    @staticmethod
    def _normalize_action(action: Action | str) -> Action:
        if isinstance(action, Action):
            return action

        action_value = action.strip()
        try:
            return Action(action_value)
        except ValueError:
            action_by_name = Action.__members__.get(action_value)
            if action_by_name is not None:
                return action_by_name
            raise

    @staticmethod
    def _normalize_status(status: AuditStatus | str) -> AuditStatus:
        if isinstance(status, AuditStatus):
            return status

        status_value = status.strip()
        try:
            return AuditStatus(status_value)
        except ValueError:
            status_by_name = AuditStatus.__members__.get(status_value)
            if status_by_name is not None:
                return status_by_name
            raise

    @staticmethod
    def _resolve_actor_id(actor: ReBACBaseUser | UserId | None) -> UserId | None:
        if actor is None:
            return None
        if isinstance(actor, ReBACBaseUser):
            return actor.id
        return actor
