from __future__ import annotations

from typing import Any, TYPE_CHECKING

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..anomaly import is_pyod_available
from ..enums import Action
from .utils import (
    _admin_model_config_or_404,
    _admin_template_response,
    _allowed_table_keys,
    _available_resource_configs,
    _apply_form_to_instance,
    _assert_table_permission,
    _resource_display_fields,
    _resource_form_fields,
    _resource_object,
    _resource_rows_context,
    _resource_select,
    _with_admin_context,
)

if TYPE_CHECKING:
    from ..fastapi_rebac import FastAPIReBAC


async def _can_access_resource_object(
    rebac: "FastAPIReBAC[Any]",
    session: AsyncSession,
    user: Any,
    config: Any,
    object_id: str,
    action: Action,
) -> bool:
    if action is Action.UPDATE and not config["allow_update"]:
        return False
    if action is Action.DELETE and not config["allow_delete"]:
        return False

    try:
        obj = await _resource_object(rebac, session, user, config, object_id, action=action)
    except HTTPException as exc:
        if exc.status_code in {
            status.HTTP_403_FORBIDDEN,
            status.HTTP_404_NOT_FOUND,
            status.HTTP_405_METHOD_NOT_ALLOWED,
        }:
            return False
        raise
    return obj is not None


def register_resource_routes(router: APIRouter, rebac: "FastAPIReBAC[Any]") -> None:
    @router.get("/", response_class=HTMLResponse, name="admin_index")
    async def admin_index(
        request: Request,
        user=Depends(rebac.staff_required),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> HTMLResponse:
        allowed_tables = await _allowed_table_keys(rebac, session, user, "READ")
        resources = _available_resource_configs(rebac, user, allowed_tables)

        return rebac.templates.TemplateResponse(
            request=request,
            name="rebac_admin/index.html",
            context=await _with_admin_context(
                rebac,
                session,
                user,
                {
                    "resources": resources,
                    "allowed_tables": sorted(allowed_tables),
                },
            ),
        )

    @router.get("/resources", response_class=HTMLResponse, name="admin_resources_page")
    async def admin_resources_page(
        request: Request,
        user=Depends(rebac.staff_required),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> HTMLResponse:
        allowed_tables = await _allowed_table_keys(rebac, session, user, "READ")
        resources = _available_resource_configs(rebac, user, allowed_tables)

        return rebac.templates.TemplateResponse(
            request=request,
            name="rebac_admin/resources.html",
            context=await _with_admin_context(rebac, session, user, {"resources": resources}),
        )

    @router.get("/resources/{table_key}", response_class=HTMLResponse, name="admin_resource_list_page")
    async def admin_resource_list_page(
        request: Request,
        table_key: str,
        user=Depends(rebac.staff_required),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> HTMLResponse:
        config = _admin_model_config_or_404(rebac, table_key)

        stmt = await _resource_select(rebac, session, user, config)
        result = await session.execute(stmt)
        rows = list(result.scalars().all())
        create_allowed = config["allow_create"] and (
            user.is_superuser or table_key in await _allowed_table_keys(rebac, session, user, "CREATE")
        )

        return await _admin_template_response(
            rebac,
            request,
            session,
            user,
            "rebac_admin/resource_list.html",
            {
                "config": config,
                "rows": await _resource_rows_context(rebac, session, request, config, rows),
                "create_allowed": create_allowed,
                "suspicious_activity_config": rebac.suspicious_activity_config
                if table_key == "suspicious_alert"
                else None,
                "pyod_available": is_pyod_available() if table_key == "suspicious_alert" else None,
            },
            include_csrf=table_key == "suspicious_alert",
        )

    @router.get("/resources/{table_key}/create", response_class=HTMLResponse, name="admin_resource_create_page")
    async def admin_resource_create_page(
        request: Request,
        table_key: str,
        user=Depends(rebac.staff_required),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> HTMLResponse:
        config = _admin_model_config_or_404(rebac, table_key)
        if not config["allow_create"]:
            raise HTTPException(status_code=405, detail="Create is not available for this resource.")

        await _assert_table_permission(rebac, session, user, table_key, Action.CREATE)
        await _assert_table_permission(rebac, session, user, table_key, Action.READ)

        return await _admin_template_response(
            rebac,
            request,
            session,
            user,
            "rebac_admin/resource_form.html",
            {
                "config": config,
                "fields": await _resource_form_fields(rebac, session, request, config, for_create=True),
                "instance": None,
                "mode": "create",
            },
            include_csrf=True,
        )

    @router.post("/resources/{table_key}/create", name="admin_resource_create_submit")
    async def admin_resource_create_submit(
        request: Request,
        table_key: str,
        user=Depends(rebac.staff_required),
        _csrf_protect: None = Depends(rebac.csrf_protect),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> RedirectResponse:
        config = _admin_model_config_or_404(rebac, table_key)
        if not config["allow_create"]:
            raise HTTPException(status_code=405, detail="Create is not available for this resource.")

        await _assert_table_permission(rebac, session, user, table_key, Action.CREATE)
        await _assert_table_permission(rebac, session, user, table_key, Action.READ)

        instance = config["model"]()
        owner_user_id = user.id if table_key in rebac.library_admin_table_keys else None
        await _apply_form_to_instance(
            rebac,
            request,
            session,
            instance,
            config,
            for_create=True,
            owner_user_id=owner_user_id,
        )

        session.add(instance)
        try:
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Could not create object. Check required and related fields.",
            ) from exc
        await session.refresh(instance)

        object_pk = getattr(instance, config["pk_attr_name"])
        await rebac.get_audit_manager(session).log_success(
            action=Action.CREATE,
            actor=user,
            table_key=table_key,
            object_id=object_pk,
            request=request,
        )

        return RedirectResponse(
            url=request.url_for(
                "admin_resource_detail_page",
                table_key=table_key,
                object_id=str(object_pk),
            ),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @router.get("/resources/{table_key}/{object_id}", response_class=HTMLResponse, name="admin_resource_detail_page")
    async def admin_resource_detail_page(
        request: Request,
        table_key: str,
        object_id: str,
        user=Depends(rebac.staff_required),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> HTMLResponse:
        config = _admin_model_config_or_404(rebac, table_key)

        instance = await _resource_object(rebac, session, user, config, object_id)
        if instance is None:
            raise HTTPException(status_code=404, detail="Object not found.")

        update_allowed = False
        if config["allow_update"]:
            update_allowed = await _can_access_resource_object(
                rebac, session, user, config, object_id, Action.UPDATE
            )

        delete_allowed = False
        if config["allow_delete"]:
            delete_allowed = await _can_access_resource_object(
                rebac, session, user, config, object_id, Action.DELETE
            )

        return await _admin_template_response(
            rebac,
            request,
            session,
            user,
            "rebac_admin/resource_detail.html",
            {
                "config": config,
                "instance": instance,
                "fields": await _resource_display_fields(rebac, session, request, config, instance),
                "update_allowed": update_allowed,
                "delete_allowed": delete_allowed,
            },
            include_csrf=True,
        )

    @router.get("/resources/{table_key}/{object_id}/edit", response_class=HTMLResponse, name="admin_resource_edit_page")
    async def admin_resource_edit_page(
        request: Request,
        table_key: str,
        object_id: str,
        user=Depends(rebac.staff_required),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> HTMLResponse:
        config = _admin_model_config_or_404(rebac, table_key)
        if not config["allow_update"]:
            raise HTTPException(status_code=405, detail="Update is not available for this resource.")

        instance = await _resource_object(rebac, session, user, config, object_id, action=Action.UPDATE)
        if instance is None:
            raise HTTPException(status_code=404, detail="Object not found.")

        return await _admin_template_response(
            rebac,
            request,
            session,
            user,
            "rebac_admin/resource_form.html",
            {
                "config": config,
                "fields": await _resource_form_fields(rebac, session, request, config, instance=instance),
                "instance": instance,
                "mode": "edit",
            },
            include_csrf=True,
        )

    @router.post("/resources/{table_key}/{object_id}/edit", name="admin_resource_edit_submit")
    async def admin_resource_edit_submit(
        request: Request,
        table_key: str,
        object_id: str,
        user=Depends(rebac.staff_required),
        _csrf_protect: None = Depends(rebac.csrf_protect),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> RedirectResponse:
        config = _admin_model_config_or_404(rebac, table_key)
        if not config["allow_update"]:
            raise HTTPException(status_code=405, detail="Update is not available for this resource.")

        instance = await _resource_object(rebac, session, user, config, object_id, action=Action.UPDATE)
        if instance is None:
            raise HTTPException(status_code=404, detail="Object not found.")

        await _apply_form_to_instance(rebac, request, session, instance, config, for_create=False)
        try:
            await session.commit()
        except IntegrityError as exc:
            await session.rollback()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Could not update object. Check required and related fields.",
            ) from exc

        object_pk = getattr(instance, config["pk_attr_name"])
        await rebac.get_audit_manager(session).log_success(
            action=Action.UPDATE,
            actor=user,
            table_key=table_key,
            object_id=object_pk,
            request=request,
        )

        return RedirectResponse(
            url=request.url_for(
                "admin_resource_detail_page",
                table_key=table_key,
                object_id=str(object_pk),
            ),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @router.get("/resources/{table_key}/{object_id}/delete", response_class=HTMLResponse, name="admin_resource_delete_page")
    async def admin_resource_delete_page(
        request: Request,
        table_key: str,
        object_id: str,
        user=Depends(rebac.staff_required),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> HTMLResponse:
        config = _admin_model_config_or_404(rebac, table_key)
        if not config["allow_delete"]:
            raise HTTPException(status_code=405, detail="Delete is not available for this resource.")

        instance = await _resource_object(rebac, session, user, config, object_id, action=Action.DELETE)
        if instance is None:
            raise HTTPException(status_code=404, detail="Object not found.")

        return await _admin_template_response(
            rebac,
            request,
            session,
            user,
            "rebac_admin/resource_delete.html",
            {
                "config": config,
                "instance": instance,
                "fields": await _resource_display_fields(rebac, session, request, config, instance),
            },
            include_csrf=True,
        )

    @router.post("/resources/{table_key}/{object_id}/delete", name="admin_resource_delete_submit")
    async def admin_resource_delete_submit(
        request: Request,
        table_key: str,
        object_id: str,
        user=Depends(rebac.staff_required),
        _csrf_protect: None = Depends(rebac.csrf_protect),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> RedirectResponse:
        config = _admin_model_config_or_404(rebac, table_key)
        if not config["allow_delete"]:
            raise HTTPException(status_code=405, detail="Delete is not available for this resource.")

        instance = await _resource_object(rebac, session, user, config, object_id, action=Action.DELETE)
        if instance is None:
            raise HTTPException(status_code=404, detail="Object not found.")

        object_pk = getattr(instance, config["pk_attr_name"])
        await session.delete(instance)
        await session.commit()

        await rebac.get_audit_manager(session).log_success(
            action=Action.DELETE,
            actor=user,
            table_key=table_key,
            object_id=object_pk,
            request=request,
        )

        return RedirectResponse(
            url=request.url_for("admin_resource_list_page", table_key=table_key),
            status_code=status.HTTP_303_SEE_OTHER,
        )
