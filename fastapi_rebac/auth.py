from __future__ import annotations

from collections.abc import AsyncGenerator, Callable
from typing import TypeVar, cast

from fastapi import Depends
from fastapi_users.authentication import (
    AuthenticationBackend,
    BearerTransport,
    CookieTransport,
    JWTStrategy,
)
from fastapi_users.db import BaseUserDatabase

from .managers.user_manager import ReBACUserManager
from .models import ReBACBaseUser
from .types import CookieSameSite, UserId

_UserT = TypeVar("_UserT", bound=ReBACBaseUser)


def build_get_user_manager(
    manager_class: type[ReBACUserManager[_UserT]],
    get_user_db: Callable[..., AsyncGenerator[BaseUserDatabase[_UserT, UserId], None]],
) -> Callable[..., AsyncGenerator[ReBACUserManager[_UserT], None]]:
    async def get_user_manager(
        user_db: BaseUserDatabase[_UserT, UserId] = Depends(get_user_db),
    ) -> AsyncGenerator[ReBACUserManager[_UserT], None]:
        manager = cast(ReBACUserManager[_UserT], cast(object, manager_class(user_db)))
        yield manager

    return get_user_manager


def build_jwt_strategy(
    *,
    secret: str,
    lifetime_seconds: int | None = 3600,
    token_audience: list[str] | None = None,
    algorithm: str = "HS256",
    public_key: str | None = None,
) -> Callable[[], JWTStrategy]:
    def get_strategy() -> JWTStrategy:
        return JWTStrategy(
            secret=secret,
            lifetime_seconds=lifetime_seconds,
            token_audience=token_audience or ["fastapi-users:auth"],
            algorithm=algorithm,
            public_key=public_key,
        )

    return get_strategy


def build_bearer_backend(
    *,
    secret: str,
    token_url: str = "auth/jwt/login",
    name: str = "jwt",
    lifetime_seconds: int | None = 3600,
    token_audience: list[str] | None = None,
    algorithm: str = "HS256",
    public_key: str | None = None,
) -> AuthenticationBackend:
    transport = BearerTransport(tokenUrl=token_url)
    strategy = build_jwt_strategy(
        secret=secret,
        lifetime_seconds=lifetime_seconds,
        token_audience=token_audience,
        algorithm=algorithm,
        public_key=public_key,
    )
    return AuthenticationBackend(
        name=name,
        transport=transport,
        get_strategy=strategy,
    )


def build_cookie_backend(
    *,
    secret: str,
    name: str = "cookie",
    cookie_name: str = "fastapiusersauth",
    cookie_max_age: int | None = 3600,
    cookie_path: str = "/",
    cookie_domain: str | None = None,
    cookie_secure: bool = True,
    cookie_httponly: bool = True,
    cookie_samesite: CookieSameSite = "lax",
    lifetime_seconds: int | None = 3600,
    token_audience: list[str] | None = None,
    algorithm: str = "HS256",
    public_key: str | None = None,
) -> AuthenticationBackend:
    transport = CookieTransport(
        cookie_name=cookie_name,
        cookie_max_age=cookie_max_age,
        cookie_path=cookie_path,
        cookie_domain=cookie_domain,
        cookie_secure=cookie_secure,
        cookie_httponly=cookie_httponly,
        cookie_samesite=cookie_samesite,
    )
    strategy = build_jwt_strategy(
        secret=secret,
        lifetime_seconds=lifetime_seconds,
        token_audience=token_audience,
        algorithm=algorithm,
        public_key=public_key,
    )
    return AuthenticationBackend(
        name=name,
        transport=transport,
        get_strategy=strategy,
    )


__all__ = [
    "ReBACUserManager",
    "build_get_user_manager",
    "build_jwt_strategy",
    "build_bearer_backend",
    "build_cookie_backend",
]
