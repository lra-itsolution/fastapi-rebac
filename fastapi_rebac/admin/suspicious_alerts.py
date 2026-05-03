from __future__ import annotations

from typing import Any, TYPE_CHECKING

from fastapi import APIRouter, Depends, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from ..anomaly import is_pyod_available, run_suspicious_activity_detection
from ..enums import Action
from .utils import _log_admin_success

if TYPE_CHECKING:
    from ..fastapi_rebac import FastAPIReBAC


def register_suspicious_alert_routes(router: APIRouter, rebac: "FastAPIReBAC[Any]") -> None:
    @router.post("/suspicious-alerts/run", name="admin_suspicious_alerts_run")
    async def admin_suspicious_alerts_run(
        request: Request,
        actor=Depends(rebac.superuser_required),
        _csrf_protect: None = Depends(rebac.csrf_protect),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> RedirectResponse:
        """Run the optional suspicious activity detectors from the admin UI.

        The MVP action is intentionally restricted to superusers because it reads
        audit data and creates new security-analysis records.
        """

        config = rebac.suspicious_activity_config
        alerts = await run_suspicious_activity_detection(
            session,
            config=config,
            commit=True,
        )

        await _log_admin_success(
            rebac,
            session,
            request,
            actor,
            action=Action.CREATE,
            table_key="suspicious_alert",
            meta={
                "operation": "run_suspicious_activity_detection",
                "enabled": config.enabled,
                "rules_enabled": config.rules_enabled,
                "pyod_enabled": config.pyod_enabled,
                "pyod_available": is_pyod_available(),
                "window_minutes": config.window_minutes,
                "created_alerts": len(alerts),
            },
        )

        return RedirectResponse(
            url=request.url_for("admin_resource_list_page", table_key="suspicious_alert"),
            status_code=status.HTTP_303_SEE_OTHER,
        )
