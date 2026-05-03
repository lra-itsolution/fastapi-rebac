from __future__ import annotations

import inspect
from typing import TYPE_CHECKING, Any, TypeVar

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordRequestForm
from fastapi_users.authentication import AuthenticationBackend
from sqlalchemy.ext.asyncio import AsyncSession

from ...models import ReBACBaseUser
from ...types import BackendName, UserId
from .config import Yandex2FAConfig
from .schemas import (
    Yandex2FADisableResult,
    Yandex2FALinkResult,
    Yandex2FALoginChallenge,
    Yandex2FAStatus,
)
from .service import (
    LINK_PURPOSE,
    Yandex2FAConfigurationError,
    Yandex2FAError,
    Yandex2FAOAuthError,
    Yandex2FAService,
    Yandex2FAStateError,
    Yandex2FAVerificationError,
)

if TYPE_CHECKING:
    from ...fastapi_rebac import FastAPIReBAC

_UserT = TypeVar("_UserT", bound=ReBACBaseUser)


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


async def _get_strategy(backend: AuthenticationBackend[Any, UserId]) -> Any:
    return await _maybe_await(backend.get_strategy())


async def _call_after_login(
    user_manager: Any,
    user: ReBACBaseUser,
    request: Request,
    response: Response,
) -> None:
    hook = getattr(user_manager, "on_after_login", None)
    if hook is None:
        return
    await _maybe_await(hook(user, request, response))


def _oauth_error_to_http(exc: Yandex2FAError) -> HTTPException:
    if isinstance(exc, Yandex2FAConfigurationError):
        return HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(exc))
    if isinstance(exc, Yandex2FAStateError):
        return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    if isinstance(exc, Yandex2FAVerificationError):
        return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc))
    if isinstance(exc, Yandex2FAOAuthError):
        return HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc))
    return HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


def get_yandex_2fa_router(
    rebac: "FastAPIReBAC[_UserT]",
    config: Yandex2FAConfig,
    *,
    backend: BackendName | AuthenticationBackend[_UserT, UserId] | None = None,
    requires_verification: bool = False,
) -> APIRouter:
    """Build a router that uses Yandex ID as a second factor.

    Include this router instead of the default FastAPI Users login router for the
    same backend when you need to enforce Yandex 2FA for linked users.
    """

    resolved_backend = rebac._resolve_backend(backend)  # noqa: SLF001 - integration within the same package
    router = APIRouter()
    session_dependency = rebac.session_dependency

    @router.post("/login", name="yandex_2fa:login")
    async def login(
        request: Request,
        credentials: OAuth2PasswordRequestForm = Depends(),
        user_manager: Any = Depends(rebac.user_manager_dependency),
        session: AsyncSession = Depends(session_dependency),
    ) -> Any:
        user = await user_manager.authenticate(credentials)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="LOGIN_BAD_CREDENTIALS",
            )
        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="LOGIN_BAD_CREDENTIALS",
            )
        if requires_verification and not getattr(user, "is_verified", False):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="LOGIN_BAD_CREDENTIALS",
            )

        service = Yandex2FAService(session, config)
        if await service.is_enabled(user.id):
            preauth, redirect_url = await service.create_login_challenge(user.id)
            return Yandex2FALoginChallenge(
                redirect_url=redirect_url,
                expires_in=config.preauth_ttl_seconds,
            )

        strategy = await _get_strategy(resolved_backend)
        login_response = await resolved_backend.login(strategy, user)
        await _call_after_login(user_manager, user, request, login_response)
        return login_response

    @router.get("/callback", name="yandex_2fa:callback")
    async def callback(
        request: Request,
        code: str | None = None,
        state: str | None = None,
        error: str | None = None,
        user_manager: Any = Depends(rebac.user_manager_dependency),
        session: AsyncSession = Depends(session_dependency),
    ) -> Any:
        if error:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error)
        if not code or not state:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Yandex callback must include code and state.",
            )

        service = Yandex2FAService(session, config)
        try:
            purpose = await service.get_preauth_purpose(state=state)
            if purpose == LINK_PURPOSE:
                binding = await service.complete_link(code=code, state=state)
                return Yandex2FALinkResult(
                    yandex_login=binding.yandex_login,
                    yandex_email=binding.yandex_email,
                )

            user_id, _binding = await service.complete_login(code=code, state=state)
        except Yandex2FAError as exc:
            raise _oauth_error_to_http(exc) from exc

        user = await session.get(rebac.user_model, user_id)
        if user is None or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="LOGIN_BAD_CREDENTIALS",
            )
        if requires_verification and not getattr(user, "is_verified", False):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="LOGIN_BAD_CREDENTIALS",
            )

        strategy = await _get_strategy(resolved_backend)
        login_response = await resolved_backend.login(strategy, user)
        await _call_after_login(user_manager, user, request, login_response)
        return login_response

    @router.get("/status", response_model=Yandex2FAStatus, name="yandex_2fa:status")
    async def status_view(
        user: _UserT = Depends(rebac.auth_required),
        session: AsyncSession = Depends(session_dependency),
    ) -> Yandex2FAStatus:
        service = Yandex2FAService(session, config)
        binding = await service.get_binding(user.id)
        return Yandex2FAStatus(
            enabled=bool(binding and binding.is_enabled),
            yandex_login=binding.yandex_login if binding else None,
            yandex_email=binding.yandex_email if binding else None,
        )

    @router.post("/link", response_model=Yandex2FALoginChallenge, name="yandex_2fa:link")
    async def link(
        user: _UserT = Depends(rebac.auth_required),
        session: AsyncSession = Depends(session_dependency),
    ) -> Yandex2FALoginChallenge:
        service = Yandex2FAService(session, config)
        _preauth, redirect_url = await service.create_link_challenge(user.id)
        return Yandex2FALoginChallenge(
            redirect_url=redirect_url,
            expires_in=config.preauth_ttl_seconds,
        )

    @router.get("/link/callback", response_model=Yandex2FALinkResult, name="yandex_2fa:link_callback")
    async def link_callback(
        code: str | None = None,
        state: str | None = None,
        error: str | None = None,
        session: AsyncSession = Depends(session_dependency),
    ) -> Yandex2FALinkResult:
        if error:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=error)
        if not code or not state:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Yandex callback must include code and state.",
            )

        service = Yandex2FAService(session, config)
        try:
            binding = await service.complete_link(code=code, state=state)
        except Yandex2FAError as exc:
            raise _oauth_error_to_http(exc) from exc

        return Yandex2FALinkResult(
            yandex_login=binding.yandex_login,
            yandex_email=binding.yandex_email,
        )

    @router.post("/disable", response_model=Yandex2FADisableResult, name="yandex_2fa:disable")
    async def disable(
        user: _UserT = Depends(rebac.auth_required),
        session: AsyncSession = Depends(session_dependency),
    ) -> Yandex2FADisableResult:
        service = Yandex2FAService(session, config)
        await service.disable(user.id)
        return Yandex2FADisableResult()

    return router
