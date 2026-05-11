from __future__ import annotations

import inspect
from typing import Any, TYPE_CHECKING

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from .redirects import path_matches_prefix, safe_relative_url
from .utils import _template_response

if TYPE_CHECKING:
    from fastapi_users.authentication import AuthenticationBackend

    from ..fastapi_rebac import FastAPIReBAC


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _admin_login_url(request: Request, *, next_url: str | None = None) -> str:
    url = str(request.url_for("admin_login_page"))
    if next_url:
        url = str(request.url_for("admin_login_page").include_query_params(next=next_url))
    return url


def _admin_login_redirect(request: Request, *, next_url: str | None = None) -> RedirectResponse:
    return RedirectResponse(
        url=_admin_login_url(request, next_url=next_url),
        status_code=status.HTTP_303_SEE_OTHER,
    )


def _admin_index_url(request: Request) -> str:
    return str(request.url_for("admin_index"))


def _admin_index_redirect(request: Request) -> RedirectResponse:
    return RedirectResponse(
        url=_admin_index_url(request),
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


def _admin_prefix(request: Request) -> str:
    admin_index_path = request.url_for("admin_index").path.rstrip("/") or "/"
    return admin_index_path


def _is_admin_target(request: Request, target_url: str | None) -> bool:
    if not target_url:
        return True
    safe_target = safe_relative_url(target_url)
    if safe_target is None:
        return True
    target_path = safe_target.split("?", 1)[0]
    return path_matches_prefix(target_path, _admin_prefix(request))


def _resolve_next(request: Request, raw_next: str | None) -> str | None:
    return safe_relative_url(raw_next)


def _login_context(user: Any, error: str | None, next_url: str | None) -> dict[str, Any]:
    return {"user": user, "error": error, "next_url": next_url}


async def _admin_login_response(
    backend: "AuthenticationBackend[Any, Any]",
    user: Any,
    request: Request,
    *,
    redirect_url: str | None = None,
) -> RedirectResponse:
    strategy = await _maybe_await(backend.get_strategy())
    login_response = await backend.login(strategy, user)
    redirect = RedirectResponse(
        url=redirect_url or _admin_index_url(request),
        status_code=status.HTTP_303_SEE_OTHER,
    )
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
        next: str | None = None,  # noqa: A002 - query parameter name
        user=Depends(rebac.current_user(optional=True, active=True)),
    ):
        next_url = _resolve_next(request, next)
        if user is not None:
            if next_url and not _is_admin_target(request, next_url):
                return RedirectResponse(url=next_url, status_code=status.HTTP_303_SEE_OTHER)
            if getattr(user, "is_staff", False):
                return RedirectResponse(
                    url=next_url or _admin_index_url(request),
                    status_code=status.HTTP_303_SEE_OTHER,
                )

        return _template_response(
            rebac,
            request,
            "rebac_admin/login.html",
            _login_context(user, None, next_url),
            include_csrf=True,
        )

    @router.post("/login", response_class=HTMLResponse, response_model=None, name="admin_login_submit")
    @router.post("/login/", response_class=HTMLResponse, response_model=None, include_in_schema=False)
    async def admin_login_submit(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
        next: str | None = Form(None),  # noqa: A002 - form field name
        _: None = Depends(rebac.csrf_protect),
        manager=Depends(rebac.user_manager_dependency),
        session: AsyncSession = Depends(rebac.session_dependency),
    ):
        next_url = _resolve_next(request, next)
        target_url = next_url or _admin_index_url(request)
        target_is_admin = _is_admin_target(request, target_url)

        credentials = _Credentials(username=username, password=password)
        user = await manager.authenticate(credentials)

        if user is None or not getattr(user, "is_active", False):
            return _template_response(
                rebac,
                request,
                "rebac_admin/login.html",
                _login_context(None, "Invalid email or password.", next_url),
                include_csrf=True,
            )

        if target_is_admin and not getattr(user, "is_staff", False):
            return _template_response(
                rebac,
                request,
                "rebac_admin/login.html",
                _login_context(None, "This account does not have staff access.", next_url),
                include_csrf=True,
            )

        request.state.rebac_login_redirect_after = target_url

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
                _login_context(None, str(exc.detail), next_url),
                include_csrf=True,
            )

        if second_factor_redirect is not None:
            return second_factor_redirect

        backend = _admin_cookie_backend(rebac)
        return await _admin_login_response(backend, user, request, redirect_url=target_url)

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
