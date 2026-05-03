from __future__ import annotations

from typing import Any, TYPE_CHECKING

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from ..enums import Action
from .utils import _admin_template_response, _log_admin_success, _visible_auth_tables_query

if TYPE_CHECKING:
    from ..fastapi_rebac import FastAPIReBAC


def register_auth_table_routes(router: APIRouter, rebac: "FastAPIReBAC[Any]") -> None:
    @router.get("/auth-tables", response_class=HTMLResponse, name="admin_auth_tables_page")
    async def admin_auth_tables_page(
        request: Request,
        actor=Depends(rebac.staff_required),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> HTMLResponse:
        auth_tables = list((await session.execute(_visible_auth_tables_query(rebac))).scalars().all())

        return await _admin_template_response(
            rebac,
            request,
            session,
            actor,
            "rebac_admin/auth_tables.html",
            {"auth_tables": auth_tables},
            include_csrf=True,
        )

    @router.post("/auth-tables/sync", name="admin_auth_tables_sync")
    async def admin_auth_tables_sync(
        request: Request,
        actor=Depends(rebac.superuser_required),
        _csrf_protect: None = Depends(rebac.csrf_protect),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> RedirectResponse:
        result = await rebac.ensure_auth_tables(session)
        await _log_admin_success(
            rebac,
            session,
            request,
            actor,
            action=Action.UPDATE,
            table_key="auth_table",
            meta={"operation": "sync", **result},
        )
        return RedirectResponse(
            url=request.url_for("admin_auth_tables_page"),
            status_code=status.HTTP_303_SEE_OTHER,
        )
