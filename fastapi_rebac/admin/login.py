from __future__ import annotations

import inspect
from typing import Any, TYPE_CHECKING

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from .utils import _template_response

if TYPE_CHECKING:
    from fastapi_users.authentication import AuthenticationBackend

    from ..fastapi_rebac import FastAPIReBAC


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _admin_login_redirect(request: Request) -> RedirectResponse:
    return RedirectResponse(
        url=str(request.url_for("admin_login_page")),
        status_code=status.HTTP_303_SEE_OTHER,
    )


def _admin_index_redirect(request: Request) -> RedirectResponse:
    return RedirectResponse(
        url=str(request.url_for("admin_index")),
        status_code=status.HTTP_303_SEE_OTHER,
    )


def _copy_set_cookie_headers(source: Any, target: Any) -> None:
    for name, value in getattr(source, "raw_headers", []):
        if name.lower() == b"set-cookie":
            target.raw_headers.append((name, value))


def _admin_cookie_backend(rebac: "FastAPIReBAC[Any]") -> "AuthenticationBackend[Any, Any]":
    for backend in rebac.auth_backends:
        transport = getattr(backend, "transport", None)
        if hasattr(transport, "cookie_name"):
            return backend
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail="Admin login requires a cookie authentication backend.",
    )


async def _admin_login_response(
    backend: "AuthenticationBackend[Any, Any]",
    user: Any,
    request: Request,
) -> RedirectResponse:
    strategy = await _maybe_await(backend.get_strategy())
    login_response = await backend.login(strategy, user)
    redirect = _admin_index_redirect(request)
    _copy_set_cookie_headers(login_response, redirect)
    return redirect


async def _admin_second_factor_redirect_if_required(
    *,
    rebac: "FastAPIReBAC[Any]",
    user: Any,
    request: Request,
    session: AsyncSession,
) -> RedirectResponse | None:
    """Run an optional second-factor hook registered by integrations.

    The core admin login remains integration-agnostic. Optional integrations can
    attach an object to ``rebac._admin_login_second_factor`` with async/sync
    methods:

    - ``validate_user(user) -> str | None`` for pre-check errors;
    - ``challenge(user=..., request=..., session=...) -> RedirectResponse | None``.
    """

    handler = getattr(rebac, "_admin_login_second_factor", None)
    if handler is None:
        return None

    validate_user = getattr(handler, "validate_user", None)
    if validate_user is not None:
        message = await _maybe_await(validate_user(user))
        if message:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(message))

    challenge = getattr(handler, "challenge", None)
    if challenge is None:
        return None

    return await _maybe_await(
        challenge(
            rebac=rebac,
            user=user,
            request=request,
            session=session,
        )
    )


def register_login_routes(router: APIRouter, rebac: "FastAPIReBAC[Any]") -> None:
    @router.get("/login", response_class=HTMLResponse, response_model=None, name="admin_login_page")
    @router.get("/login/", response_class=HTMLResponse, response_model=None, include_in_schema=False)
    async def admin_login_page(
        request: Request,
        user=Depends(rebac.current_user(optional=True, active=True)),
    ):
        if user is not None and getattr(user, "is_staff", False):
            return _admin_index_redirect(request)

        return _template_response(
            rebac,
            request,
            "rebac_admin/login.html",
            {"user": user, "error": None},
            include_csrf=True,
        )

    @router.post("/login", response_class=HTMLResponse, response_model=None, name="admin_login_submit")
    @router.post("/login/", response_class=HTMLResponse, response_model=None, include_in_schema=False)
    async def admin_login_submit(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
        _: None = Depends(rebac.csrf_protect),
        manager=Depends(rebac.user_manager_dependency),
        session: AsyncSession = Depends(rebac.session_dependency),
    ):
        credentials = _Credentials(username=username, password=password)
        user = await manager.authenticate(credentials)

        if user is None or not getattr(user, "is_active", False):
            return _template_response(
                rebac,
                request,
                "rebac_admin/login.html",
                {"user": None, "error": "Invalid email or password."},
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

        try:
            second_factor_redirect = await _admin_second_factor_redirect_if_required(
                rebac=rebac,
                user=user,
                request=request,
                session=session,
            )
        except HTTPException as exc:
            return _template_response(
                rebac,
                request,
                "rebac_admin/login.html",
                {"user": None, "error": str(exc.detail)},
                include_csrf=True,
            )

        if second_factor_redirect is not None:
            return second_factor_redirect

        backend = _admin_cookie_backend(rebac)
        return await _admin_login_response(backend, user, request)

    @router.post("/logout", response_model=None, name="admin_logout_submit")
    @router.post("/logout/", response_model=None, include_in_schema=False)
    async def admin_logout_submit(
        request: Request,
        _: None = Depends(rebac.csrf_protect),
    ):
        backend = _admin_cookie_backend(rebac)
        transport = getattr(backend, "transport", None)
        redirect = _admin_login_redirect(request)

        cookie_name = getattr(transport, "cookie_name", None)
        if cookie_name:
            redirect.delete_cookie(
                key=cookie_name,
                path=getattr(transport, "cookie_path", "/"),
                domain=getattr(transport, "cookie_domain", None),
            )

        return redirect


class _Credentials:
    def __init__(self, *, username: str, password: str) -> None:
        self.username = username
        self.password = password
        self.scopes: list[str] = []
        self.client_id: str | None = None
        self.client_secret: str | None = None
