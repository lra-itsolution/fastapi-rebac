from __future__ import annotations

from typing import Any, Generic, TypeVar

from fastapi import Request, Response
from fastapi_users import BaseUserManager, UUIDIDMixin
from fastapi_users.exceptions import InvalidPasswordException

from ..models import ReBACBaseUser
from ..types import JSONObject, UserId

_UserT = TypeVar("_UserT", bound=ReBACBaseUser)


class ReBACUserManager(UUIDIDMixin, BaseUserManager[_UserT, UserId], Generic[_UserT]):
    reset_password_token_secret: str = "CHANGE_ME"
    verification_token_secret: str = "CHANGE_ME"

    async def validate_password(self, password: str, user: _UserT | dict[str, Any]) -> None:
        if len(password) < 8:
            raise InvalidPasswordException(
                reason="Password should be at least 8 characters.",
            )

    async def on_after_register(
        self,
        user: _UserT,
        request: Request | None = None,
    ) -> None:
        return None

    async def on_after_login(
        self,
        user: _UserT,
        request: Request | None = None,
        response: Response | None = None,
    ) -> None:
        return None

    async def on_after_forgot_password(
        self,
        user: _UserT,
        token: str,
        request: Request | None = None,
    ) -> None:
        return None

    async def on_after_request_verify(
        self,
        user: _UserT,
        token: str,
        request: Request | None = None,
    ) -> None:
        return None

    async def on_after_verify(
        self,
        user: _UserT,
        request: Request | None = None,
    ) -> None:
        return None

    async def admin_hash_password(
        self,
        *,
        email: str,
        password: str,
        context: JSONObject | dict[str, Any] | None = None,
    ) -> str:
        validation_user: dict[str, Any] = {
            "email": email,
            **(context or {}),
        }
        await self.validate_password(password, validation_user)
        return self.password_helper.hash(password)

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
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "email": email,
            "is_active": is_active,
            "is_superuser": is_superuser,
            "is_staff": is_staff,
            "is_verified": is_verified,
        }
        if extra:
            payload.update(extra)

        payload["hashed_password"] = await self.admin_hash_password(
            email=email,
            password=password,
            context=payload,
        )
        return payload

    @staticmethod
    async def admin_prepare_update_dict(
        user: _UserT,
        *,
        email: str | None = None,
        is_active: bool | None = None,
        is_superuser: bool | None = None,
        is_staff: bool | None = None,
        is_verified: bool | None = None,
        extra: JSONObject | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        update_dict: dict[str, Any] = {}

        if email is not None and email != user.email:
            update_dict["email"] = email
        if is_active is not None and is_active != user.is_active:
            update_dict["is_active"] = is_active
        if is_superuser is not None and user.is_superuser != is_superuser:
            update_dict["is_superuser"] = is_superuser
        if is_staff is not None and getattr(user, "is_staff", False) != is_staff:
            update_dict["is_staff"] = is_staff
        if is_verified is not None and getattr(user, "is_verified", False) != is_verified:
            update_dict["is_verified"] = is_verified

        if extra:
            for key, value in extra.items():
                if getattr(user, key, None) != value:
                    update_dict[key] = value

        return update_dict

    async def admin_set_password(
        self,
        user: _UserT,
        *,
        password: str,
    ) -> str:
        return await self.admin_hash_password(
            email=user.email,
            password=password,
            context={"id": user.id},
        )


__all__ = ["ReBACUserManager"]
