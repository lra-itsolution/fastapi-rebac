from __future__ import annotations

from typing import Any, TYPE_CHECKING

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import false, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..enums import Action
from ..models import AuthTable, Group, GroupMembership, GroupPermission
from .utils import (
    _admin_template_response,
    _coerce_pk_value,
    _display_value_for_model_pk,
    _format_scalar_value,
    _log_admin_success,
    _parse_action,
    _selected_or_manual,
    _visible_auth_tables_for_user,
    _with_admin_context,
    _can_admin_update_table,
    _can_admin_delegate_permission,
)

if TYPE_CHECKING:
    from ..fastapi_rebac import FastAPIReBAC


async def _get_visible_group_or_404(
    rebac: "FastAPIReBAC[Any]",
    session: AsyncSession,
    actor: Any,
    group_id: str,
) -> Group:
    group_pk = _coerce_pk_value(Group, "id", group_id)
    if getattr(actor, "is_superuser", False):
        group_obj = await session.get(Group, group_pk)
    else:
        group_obj = await rebac.resolve_require_object(
            Action.READ,
            Group.created_by_id,
            group_pk,
            user=actor,
            session=session,
        )
    if group_obj is None:
        raise HTTPException(status_code=404, detail="Group not found.")
    return group_obj


async def _get_visible_user_or_404(
    rebac: "FastAPIReBAC[Any]",
    session: AsyncSession,
    actor: Any,
    user_id: str,
) -> Any:
    user_pk = _coerce_pk_value(rebac.user_model, "id", user_id)
    if getattr(actor, "is_superuser", False):
        user_obj = await session.get(rebac.user_model, user_pk)
    else:
        user_obj = await rebac.resolve_require_object(
            Action.READ,
            rebac.user_model.id,
            user_pk,
            user=actor,
            session=session,
        )
    if user_obj is None:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User is not visible.")
    return user_obj


async def _user_choices(rebac: "FastAPIReBAC[Any]", session: AsyncSession) -> list[Any]:
    return list((await session.execute(select(rebac.user_model).order_by(rebac.user_model.email))).scalars().all())


async def _can_read_user_table(
    rebac: "FastAPIReBAC[Any]",
    session: AsyncSession,
    actor: Any,
) -> bool:
    if getattr(actor, "is_superuser", False):
        return True

    table_key = str(getattr(rebac.user_model, "__tablename__", "user"))
    return await rebac.get_access_manager(session).can(
        user=actor,
        action=Action.READ,
        table_key=table_key,
    )


async def _visible_user_choices(
    rebac: "FastAPIReBAC[Any]",
    session: AsyncSession,
    actor: Any,
    *,
    exclude_user_ids: set[Any] | None = None,
) -> list[Any]:
    if getattr(actor, "is_superuser", False):
        stmt = select(rebac.user_model)
    else:
        if not await _can_read_user_table(rebac, session, actor):
            return []
        stmt = await rebac.resolve_accessible_select(
            rebac.user_model.id,
            user=actor,
            session=session,
        )
    if exclude_user_ids:
        stmt = stmt.where(rebac.user_model.id.not_in(exclude_user_ids))
    stmt = stmt.order_by(rebac.user_model.email)
    return list((await session.execute(stmt)).scalars().all())


def _filter_auth_tables_for_new_permissions(
    auth_tables: list[AuthTable],
    existing_permissions: list[GroupPermission],
) -> list[AuthTable]:
    existing_actions_by_table: dict[Any, set[Action]] = {}
    for permission in existing_permissions:
        existing_actions_by_table.setdefault(permission.table_id, set()).add(permission.action)
    all_actions = set(Action)
    return [table for table in auth_tables if existing_actions_by_table.get(table.id, set()) != all_actions]


async def _ensure_can_manage_group_acl(
    rebac: "FastAPIReBAC[Any]",
    session: AsyncSession,
    actor: Any,
    group_id: str,
) -> Group:
    group_obj = await _get_visible_group_or_404(rebac, session, actor, group_id)
    if not await _can_admin_update_table(rebac, session, actor, str(Group.__tablename__)):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="UPDATE permission on the group table is required.",
        )
    return group_obj


async def _ensure_group_exists(session: AsyncSession, group_pk: Any | None) -> None:
    if group_pk is None:
        return
    if await session.get(Group, group_pk) is None:
        raise HTTPException(status_code=400, detail="Selected group does not exist.")


async def _ensure_user_exists(rebac: "FastAPIReBAC[Any]", session: AsyncSession, user_pk: Any | None) -> None:
    if user_pk is None:
        return
    if await session.get(rebac.user_model, user_pk) is None:
        raise HTTPException(status_code=400, detail="Selected user does not exist.")


async def _ensure_auth_table_exists(session: AsyncSession, table_pk: Any | None) -> None:
    if table_pk is None:
        return
    if await session.get(AuthTable, table_pk) is None:
        raise HTTPException(status_code=400, detail="Selected table does not exist.")


def register_group_routes(router: APIRouter, rebac: "FastAPIReBAC[Any]") -> None:
    @router.get("/groups", response_class=HTMLResponse, name="admin_groups_page")
    async def admin_groups_page(
        request: Request,
        actor=Depends(rebac.staff_required),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> HTMLResponse:
        if actor.is_superuser:
            group_stmt = select(Group)
        else:
            group_stmt = await rebac.resolve_accessible_select(
                Group.created_by_id,
                user=actor,
                session=session,
            )
        group_stmt = group_stmt.order_by(Group.name)
        groups = list((await session.execute(group_stmt)).scalars().all())
        auth_tables = await _visible_auth_tables_for_user(rebac, session, actor)

        group_rows = []
        for group in groups:
            group_rows.append(
                {
                    "obj": group,
                    "created_by": await _display_value_for_model_pk(
                        rebac, session, request, rebac.user_model, group.created_by_id
                    ),
                    "created_at": _format_scalar_value(getattr(group, "created_at", None)),
                    "updated_at": _format_scalar_value(getattr(group, "updated_at", None)),
                }
            )

        return rebac.templates.TemplateResponse(
            request=request,
            name="rebac_admin/groups.html",
            context=await _with_admin_context(
                rebac,
                session,
                actor,
                {
                    "groups": groups,
                    "group_rows": group_rows,
                    "auth_tables": auth_tables,
                    "create_allowed": actor.is_superuser,
                },
            ),
        )

    @router.get("/groups/create", response_class=HTMLResponse, name="admin_group_create_page")
    async def admin_group_create_page(
        request: Request,
        actor=Depends(rebac.superuser_required),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> HTMLResponse:
        return await _admin_template_response(
            rebac,
            request,
            session,
            actor,
            "rebac_admin/group_form.html",
            {"group_obj": None, "mode": "create"},
            include_csrf=True,
        )

    @router.post("/groups/create", name="admin_group_create_submit")
    async def admin_group_create_submit(
        request: Request,
        name: str = Form(...),
        share_members_visibility: bool = Form(False),
        share_creator_visibility: bool = Form(False),
        actor=Depends(rebac.superuser_required),
        _csrf_protect: None = Depends(rebac.csrf_protect),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> RedirectResponse:
        group_obj = Group(
            name=name,
            created_by_id=actor.id,
            share_members_visibility=share_members_visibility,
            share_creator_visibility=share_creator_visibility,
        )
        session.add(group_obj)
        await session.commit()
        await session.refresh(group_obj)
        await _log_admin_success(
            rebac,
            session,
            request,
            actor,
            action=Action.CREATE,
            table_key=str(Group.__tablename__),
            object_id=group_obj.id,
            meta={"name": group_obj.name},
        )

        return RedirectResponse(
            url=request.url_for("admin_group_detail_page", group_id=str(group_obj.id)),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @router.get("/groups/{group_id}", response_class=HTMLResponse, name="admin_group_detail_page")
    async def admin_group_detail_page(
        request: Request,
        group_id: str,
        actor=Depends(rebac.staff_required),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> HTMLResponse:
        group_obj = await _get_visible_group_or_404(rebac, session, actor, group_id)
        group_pk = group_obj.id
        can_read_users = await _can_read_user_table(rebac, session, actor)
        visible_users = await _visible_user_choices(rebac, session, actor) if can_read_users else []
        visible_user_ids = {user_obj.id for user_obj in visible_users}
        members_stmt = select(GroupMembership).where(GroupMembership.group_id == group_pk)
        if not getattr(actor, "is_superuser", False):
            if visible_user_ids:
                members_stmt = members_stmt.where(GroupMembership.user_id.in_(visible_user_ids))
            else:
                members_stmt = members_stmt.where(false())
        members = list((await session.execute(members_stmt)).scalars().all())
        visible_auth_tables = await _visible_auth_tables_for_user(rebac, session, actor)
        visible_auth_table_ids = {table.id for table in visible_auth_tables}
        permissions_stmt = select(GroupPermission).where(GroupPermission.group_id == group_pk)
        if not getattr(actor, "is_superuser", False):
            permissions_stmt = permissions_stmt.where(GroupPermission.table_id.in_(visible_auth_table_ids))
        permissions = list((await session.execute(permissions_stmt)).scalars().all())
        auth_tables = _filter_auth_tables_for_new_permissions(visible_auth_tables, permissions)
        existing_member_ids = {membership.user_id for membership in members}
        user_choices = [
            user_obj
            for user_obj in visible_users
            if user_obj.id not in existing_member_ids
        ]
        can_manage_group_acl = await _can_admin_update_table(rebac, session, actor, str(Group.__tablename__))
        can_manage_group_members = can_manage_group_acl and can_read_users

        member_rows = []
        for membership in members:
            member_rows.append(
                {
                    "id": membership.id,
                    "user": await _display_value_for_model_pk(
                        rebac, session, request, rebac.user_model, membership.user_id
                    ),
                    "created_by": await _display_value_for_model_pk(
                        rebac, session, request, rebac.user_model, membership.created_by_id
                    ) if membership.created_by_id in visible_user_ids else None,
                }
            )

        permission_rows = []
        for permission in permissions:
            permission_rows.append(
                {
                    "id": permission.id,
                    "table": await _display_value_for_model_pk(
                        rebac, session, request, AuthTable, permission.table_id
                    ),
                    "action": permission.action,
                    "granted_by": await _display_value_for_model_pk(
                        rebac, session, request, rebac.user_model, permission.granted_by_id
                    ) if getattr(permission, "granted_by_id", None) is not None else None,
                }
            )

        created_by_display = await _display_value_for_model_pk(
            rebac, session, request, rebac.user_model, group_obj.created_by_id
        )

        return await _admin_template_response(
            rebac,
            request,
            session,
            actor,
            "rebac_admin/group_detail.html",
            {
                "group_obj": group_obj,
                "members": members,
                "permissions": permissions,
                "member_rows": member_rows,
                "permission_rows": permission_rows,
                "created_by_display": created_by_display,
                "created_at_display": _format_scalar_value(getattr(group_obj, "created_at", None)),
                "updated_at_display": _format_scalar_value(getattr(group_obj, "updated_at", None)),
                "auth_tables": auth_tables,
                "user_choices": user_choices,
                "actions": list(Action),
                "can_update_group": actor.is_superuser,
                "can_delete_group": actor.is_superuser,
                "can_read_membership": can_manage_group_members,
                "can_create_membership": can_manage_group_members,
                "can_delete_membership": can_manage_group_members,
                "can_read_permission": can_manage_group_acl,
                "can_create_permission": can_manage_group_acl,
                "can_delete_permission": can_manage_group_acl,
            },
            include_csrf=True,
        )

    @router.get("/groups/{group_id}/edit", response_class=HTMLResponse, name="admin_group_edit_page")
    async def admin_group_edit_page(
        request: Request,
        group_id: str,
        actor=Depends(rebac.superuser_required),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> HTMLResponse:
        group_obj = await _get_visible_group_or_404(rebac, session, actor, group_id)
        return await _admin_template_response(
            rebac,
            request,
            session,
            actor,
            "rebac_admin/group_form.html",
            {"group_obj": group_obj, "mode": "edit"},
            include_csrf=True,
        )

    @router.post("/groups/{group_id}/edit", name="admin_group_edit_submit")
    async def admin_group_edit_submit(
        request: Request,
        group_id: str,
        name: str = Form(...),
        share_members_visibility: bool = Form(False),
        share_creator_visibility: bool = Form(False),
        actor=Depends(rebac.superuser_required),
        _csrf_protect: None = Depends(rebac.csrf_protect),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> RedirectResponse:
        group_obj = await _get_visible_group_or_404(rebac, session, actor, group_id)
        group_obj.name = name
        group_obj.share_members_visibility = share_members_visibility
        group_obj.share_creator_visibility = share_creator_visibility
        await session.commit()
        await _log_admin_success(
            rebac,
            session,
            request,
            actor,
            action=Action.UPDATE,
            table_key=str(Group.__tablename__),
            object_id=group_obj.id,
            meta={"name": group_obj.name},
        )

        return RedirectResponse(
            url=request.url_for("admin_group_detail_page", group_id=group_id),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @router.get("/groups/{group_id}/delete", response_class=HTMLResponse, name="admin_group_delete_page")
    async def admin_group_delete_page(
        request: Request,
        group_id: str,
        actor=Depends(rebac.superuser_required),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> HTMLResponse:
        group_obj = await _get_visible_group_or_404(rebac, session, actor, group_id)
        return await _admin_template_response(
            rebac,
            request,
            session,
            actor,
            "rebac_admin/group_delete.html",
            {"group_obj": group_obj},
            include_csrf=True,
        )

    @router.post("/groups/{group_id}/delete", name="admin_group_delete_submit")
    async def admin_group_delete_submit(
        request: Request,
        group_id: str,
        actor=Depends(rebac.superuser_required),
        _csrf_protect: None = Depends(rebac.csrf_protect),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> RedirectResponse:
        group_obj = await _get_visible_group_or_404(rebac, session, actor, group_id)
        group_pk = group_obj.id
        group_name = group_obj.name
        await session.delete(group_obj)
        await session.commit()
        await _log_admin_success(
            rebac,
            session,
            request,
            actor,
            action=Action.DELETE,
            table_key=str(Group.__tablename__),
            object_id=group_pk,
            meta={"name": group_name},
        )
        return RedirectResponse(
            url=request.url_for("admin_groups_page"),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @router.post("/groups/{group_id}/members/add", name="admin_group_add_member")
    async def admin_group_add_member(
        request: Request,
        group_id: str,
        actor=Depends(rebac.staff_required),
        _csrf_protect: None = Depends(rebac.csrf_protect),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> RedirectResponse:
        form = await request.form()
        user_raw = _selected_or_manual(form, "user_id_select", "user_id", require_both=True)
        if user_raw is None:
            raise HTTPException(status_code=400, detail="User is required.")

        group_obj = await _ensure_can_manage_group_acl(rebac, session, actor, group_id)
        group_pk = group_obj.id
        user_pk = _coerce_pk_value(rebac.user_model, "id", user_raw)
        await _get_visible_user_or_404(rebac, session, actor, str(user_pk))
        existing = await session.execute(
            select(GroupMembership).where(
                GroupMembership.group_id == group_pk,
                GroupMembership.user_id == user_pk,
            )
        )
        if existing.scalar_one_or_none() is None:
            membership = GroupMembership(group_id=group_pk, user_id=user_pk, created_by_id=actor.id)
            session.add(membership)
            await session.commit()
            await session.refresh(membership)
            await _log_admin_success(
                rebac,
                session,
                request,
                actor,
                action=Action.CREATE,
                table_key=str(GroupMembership.__tablename__),
                object_id=membership.id,
                meta={
                    "group_id": str(group_pk),
                    "user_id": str(user_pk),
                    "created_by_id": str(actor.id),
                    "source": "group_detail",
                },
            )
        return RedirectResponse(
            url=request.url_for("admin_group_detail_page", group_id=group_id),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @router.post("/groups/{group_id}/members/{membership_id}/delete", name="admin_group_remove_member")
    async def admin_group_remove_member(
        request: Request,
        group_id: str,
        membership_id: str,
        actor=Depends(rebac.staff_required),
        _csrf_protect: None = Depends(rebac.csrf_protect),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> RedirectResponse:
        group_obj = await _ensure_can_manage_group_acl(rebac, session, actor, group_id)
        group_pk = group_obj.id
        membership_pk = _coerce_pk_value(GroupMembership, "id", membership_id)
        membership = (
            await session.execute(
                select(GroupMembership).where(
                    GroupMembership.id == membership_pk,
                    GroupMembership.group_id == group_pk,
                )
            )
        ).scalar_one_or_none()
        if membership is not None:
            user_pk = membership.user_id
            created_by_pk = membership.created_by_id
            await _get_visible_user_or_404(rebac, session, actor, str(user_pk))
            await session.delete(membership)
            await session.commit()
            await _log_admin_success(
                rebac,
                session,
                request,
                actor,
                action=Action.DELETE,
                table_key=str(GroupMembership.__tablename__),
                object_id=membership_pk,
                meta={
                    "group_id": str(group_pk),
                    "user_id": str(user_pk),
                    "created_by_id": str(created_by_pk),
                    "source": "group_detail",
                },
            )
        return RedirectResponse(
            url=request.url_for("admin_group_detail_page", group_id=group_id),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @router.post("/groups/{group_id}/permissions/add", name="admin_group_add_permission")
    async def admin_group_add_permission(
        request: Request,
        group_id: str,
        action: str = Form(...),
        actor=Depends(rebac.staff_required),
        _csrf_protect: None = Depends(rebac.csrf_protect),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> RedirectResponse:
        form = await request.form()
        table_raw = _selected_or_manual(form, "table_id_select", "table_id", require_both=True)
        if table_raw is None:
            raise HTTPException(status_code=400, detail="Table is required.")

        group_obj = await _ensure_can_manage_group_acl(rebac, session, actor, group_id)
        group_pk = group_obj.id
        table_pk = _coerce_pk_value(AuthTable, "id", table_raw)
        await _ensure_auth_table_exists(session, table_pk)
        action_enum = _parse_action(action)
        if not await _can_admin_delegate_permission(rebac, session, actor, table_pk, action_enum):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You may grant only permissions that you have yourself.",
            )
        existing = await session.execute(
            select(GroupPermission).where(
                GroupPermission.group_id == group_pk,
                GroupPermission.table_id == table_pk,
                GroupPermission.action == action_enum,
            )
        )
        if existing.scalar_one_or_none() is None:
            permission = GroupPermission(
                group_id=group_pk,
                table_id=table_pk,
                action=action_enum,
                granted_by_id=actor.id,
            )
            session.add(permission)
            await session.commit()
            await session.refresh(permission)
            await _log_admin_success(
                rebac,
                session,
                request,
                actor,
                action=Action.CREATE,
                table_key=str(GroupPermission.__tablename__),
                object_id=permission.id,
                meta={
                    "group_id": str(group_pk),
                    "table_id": str(table_pk),
                    "permission_action": action_enum.value,
                },
            )

        return RedirectResponse(
            url=request.url_for("admin_group_detail_page", group_id=group_id),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @router.post("/groups/{group_id}/permissions/{permission_id}/delete", name="admin_group_remove_permission")
    async def admin_group_remove_permission(
        request: Request,
        group_id: str,
        permission_id: str,
        actor=Depends(rebac.staff_required),
        _csrf_protect: None = Depends(rebac.csrf_protect),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> RedirectResponse:
        group_obj = await _ensure_can_manage_group_acl(rebac, session, actor, group_id)
        group_pk = group_obj.id
        permission_pk = _coerce_pk_value(GroupPermission, "id", permission_id)
        permission = (
            await session.execute(
                select(GroupPermission).where(
                    GroupPermission.id == permission_pk,
                    GroupPermission.group_id == group_pk,
                )
            )
        ).scalar_one_or_none()
        if permission is not None:
            table_pk = permission.table_id
            if not await _can_admin_delegate_permission(rebac, session, actor, table_pk, permission.action):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="You may revoke only permissions that you have yourself.",
                )
            permission_action = permission.action.value
            await session.delete(permission)
            await session.commit()
            await _log_admin_success(
                rebac,
                session,
                request,
                actor,
                action=Action.DELETE,
                table_key=str(GroupPermission.__tablename__),
                object_id=permission_pk,
                meta={
                    "group_id": str(group_pk),
                    "table_id": str(table_pk),
                    "permission_action": permission_action,
                },
            )

        return RedirectResponse(
            url=request.url_for("admin_group_detail_page", group_id=group_id),
            status_code=status.HTTP_303_SEE_OTHER,
        )
