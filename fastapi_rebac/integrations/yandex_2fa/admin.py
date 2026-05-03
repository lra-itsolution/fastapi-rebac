from __future__ import annotations

import inspect
from typing import TYPE_CHECKING, Any, TypeVar

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi_users.authentication import AuthenticationBackend
from sqlalchemy.ext.asyncio import AsyncSession

from ...admin.utils import _template_response
from ...models import ReBACBaseUser
from ...types import BackendName, UserId
from .config import Yandex2FAConfig
from .service import Yandex2FAError, Yandex2FAService

if TYPE_CHECKING:
    from ...fastapi_rebac import FastAPIReBAC

_UserT = TypeVar("_UserT", bound=ReBACBaseUser)


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _copy_set_cookie_headers(source: Any, target: Any) -> None:
    for name, value in getattr(source, "raw_headers", []):
        if name.lower() == b"set-cookie":
            target.raw_headers.append((name, value))


def _resolve_admin_backend(
    rebac: "FastAPIReBAC[_UserT]",
    backend: BackendName | AuthenticationBackend[_UserT, UserId] | None,
) -> AuthenticationBackend[_UserT, UserId]:
    if backend is not None:
        return rebac._resolve_backend(backend)  # noqa: SLF001 - integration inside package boundary

    for candidate in rebac.auth_backends:
        transport = getattr(candidate, "transport", None)
        if hasattr(transport, "cookie_name"):
            return candidate

    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Yandex 2FA admin integration requires a cookie authentication backend.",
    )


class Yandex2FAAdminHandler:
    """Small hook object used by the core admin login without Yandex-specific imports."""

    def __init__(
        self,
        *,
        config: Yandex2FAConfig,
        redirect_uri: str,
        requires_verification: bool = False,
    ) -> None:
        self.config = config
        self.redirect_uri = redirect_uri
        self.requires_verification = requires_verification

    def validate_user(self, user: Any) -> str | None:
        if self.requires_verification and not getattr(user, "is_verified", False):
            return "This account is not verified."
        return None

    async def challenge(
        self,
        *,
        rebac: "FastAPIReBAC[Any]",
        user: Any,
        request: Request,
        session: AsyncSession,
    ) -> RedirectResponse | None:
        service = Yandex2FAService(session, self.config)
        if not await service.is_enabled(user.id):
            return None

        _preauth, redirect_url = await service.create_login_challenge(
            user.id,
            redirect_after=str(request.url_for("admin_index")),
            redirect_uri=self.redirect_uri,
        )
        return RedirectResponse(
            url=redirect_url,
            status_code=status.HTTP_303_SEE_OTHER,
        )


def _error_message(exc: Exception) -> str:
    message = str(exc).strip()
    return message or "Yandex 2FA verification failed. Please try again."


async def _admin_login_response(
    backend: AuthenticationBackend[Any, UserId],
    user: Any,
    request: Request,
) -> RedirectResponse:
    strategy = await _maybe_await(backend.get_strategy())
    login_response = await backend.login(strategy, user)
    redirect = RedirectResponse(
        url=str(request.url_for("admin_index")),
        status_code=status.HTTP_303_SEE_OTHER,
    )
    _copy_set_cookie_headers(login_response, redirect)
    return redirect


def get_yandex_2fa_admin_router(
    rebac: "FastAPIReBAC[_UserT]",
    config: Yandex2FAConfig,
    *,
    backend: BackendName | AuthenticationBackend[_UserT, UserId] | None = None,
    redirect_uri: str | None = None,
    requires_verification: bool = False,
) -> APIRouter:
    """Enable Yandex ID as a second factor for the bundled HTML admin login.

    The integration remains optional and lives outside ``FastAPIReBAC``. Calling
    this function registers an integration-agnostic second-factor hook on the
    ReBAC instance and returns a router with the admin callback endpoint. Include
    the returned router under the same prefix as the admin panel, usually
    ``/admin``.
    """

    resolved_backend = _resolve_admin_backend(rebac, backend)
    effective_redirect_uri = redirect_uri or config.redirect_uri
    setattr(
        rebac,
        "_admin_login_second_factor",
        Yandex2FAAdminHandler(
            config=config,
            redirect_uri=effective_redirect_uri,
            requires_verification=requires_verification,
        ),
    )

    router = APIRouter()

    @router.get(
        "/yandex-2fa/callback",
        response_class=HTMLResponse,
        response_model=None,
        name="admin_yandex_2fa_callback",
    )
    @router.get(
        "/yandex-2fa/callback/",
        response_class=HTMLResponse,
        response_model=None,
        include_in_schema=False,
    )
    async def admin_yandex_2fa_callback(
        request: Request,
        code: str | None = None,
        state: str | None = None,
        error: str | None = None,
        session: AsyncSession = Depends(rebac.session_dependency),
    ):
        if error:
            return _template_response(
                rebac,
                request,
                "rebac_admin/login.html",
                {"user": None, "error": error},
                include_csrf=True,
            )

        if not code or not state:
            return _template_response(
                rebac,
                request,
                "rebac_admin/login.html",
                {"user": None, "error": "Yandex callback must include code and state."},
                include_csrf=True,
            )

        service = Yandex2FAService(session, config)
        try:
            user_id, _binding = await service.complete_login(
                code=code,
                state=state,
                redirect_uri=effective_redirect_uri,
            )
        except Yandex2FAError as exc:
            return _template_response(
                rebac,
                request,
                "rebac_admin/login.html",
                {"user": None, "error": _error_message(exc)},
                include_csrf=True,
            )

        user = await session.get(rebac.user_model, user_id)
        if user is None or not getattr(user, "is_active", False):
            return _template_response(
                rebac,
                request,
                "rebac_admin/login.html",
                {"user": None, "error": "Invalid or inactive user."},
                include_csrf=True,
            )

        if not getattr(user, "is_staff", False):
            return _template_response(
                rebac,
                request,
                "rebac_admin/login.html",
                {"user": None, "error": "This account does not have staff access."},
                include_csrf=True,
            )

        if requires_verification and not getattr(user, "is_verified", False):
            return _template_response(
                rebac,
                request,
                "rebac_admin/login.html",
                {"user": None, "error": "This account is not verified."},
                include_csrf=True,
            )

        return await _admin_login_response(resolved_backend, user, request)

    return router
