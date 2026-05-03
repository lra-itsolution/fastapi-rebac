from __future__ import annotations

from typing import Any, TYPE_CHECKING

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from .utils import _allowed_table_keys

if TYPE_CHECKING:
    from ..fastapi_rebac import FastAPIReBAC


def register_api_routes(router: APIRouter, rebac: "FastAPIReBAC[Any]") -> None:
    @router.get("/api/resources", name="admin_resources_api")
    async def admin_resources_api(
        user=Depends(rebac.staff_required),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> dict[str, Any]:
        allowed_tables = await _allowed_table_keys(rebac, session, user, "READ")
        items = [
            {
                "table_key": item["table_key"],
                "title": item["title"],
                "admin_view": item["admin_view"],
            }
            for item in rebac.get_registered_admin_models()
            if user.is_superuser or item["table_key"] in allowed_tables
        ]
        return {"items": items, "count": len(items)}
