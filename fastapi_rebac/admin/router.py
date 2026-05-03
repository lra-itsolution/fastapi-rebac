from __future__ import annotations

from typing import Any, TYPE_CHECKING

from fastapi import APIRouter

from .api import register_api_routes
from .auth_tables import register_auth_table_routes
from .groups import register_group_routes
from .login import register_login_routes
from .resources import register_resource_routes
from .suspicious_alerts import register_suspicious_alert_routes
from .users import register_user_routes

if TYPE_CHECKING:
    from ..fastapi_rebac import FastAPIReBAC


def build_admin_router(rebac: "FastAPIReBAC[Any]") -> APIRouter:
    router = APIRouter(tags=["rebac-admin"])

    register_login_routes(router, rebac)
    register_resource_routes(router, rebac)
    register_user_routes(router, rebac)
    register_group_routes(router, rebac)
    register_auth_table_routes(router, rebac)
    register_suspicious_alert_routes(router, rebac)
    register_api_routes(router, rebac)

    return router
