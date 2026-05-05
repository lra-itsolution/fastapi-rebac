from __future__ import annotations

from typing import Any, TYPE_CHECKING

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy import false, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..enums import Action
from ..models import AuthTable, Group, GroupMembership, UserPermission
from .utils import (
    _admin_template_response,
    _coerce_pk_value,
    _display_value_for_model_pk,
    _format_scalar_value,
    _log_admin_success,
    _parse_action,
    _user_manager_update_user,
    _visible_auth_tables_for_user,
    _with_admin_context,
    _can_admin_update_table,
    _can_admin_delegate_permission,
)

if TYPE_CHECKING:
    from ..fastapi_rebac import FastAPIReBAC


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
        raise HTTPException(status_code=404, detail="User not found.")
    return user_obj


async def _ensure_unique_user_field(
    rebac: "FastAPIReBAC[Any]",
    session: AsyncSession,
    field_name: str,
    value: str,
    *,
    exclude_user_id: Any | None = None,
) -> None:
    field = getattr(rebac.user_model, field_name)
    stmt = select(rebac.user_model).where(field == value)
    if exclude_user_id is not None:
        stmt = stmt.where(rebac.user_model.id != exclude_user_id)

    existing = await session.execute(stmt)
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"User with this {field_name} already exists.",
        )


async def _user_choices(rebac: "FastAPIReBAC[Any]", session: AsyncSession, *, exclude_user_id: Any | None = None) -> list[Any]:
    stmt = select(rebac.user_model).order_by(rebac.user_model.email)
    if exclude_user_id is not None:
        stmt = stmt.where(rebac.user_model.id != exclude_user_id)
    return list((await session.execute(stmt)).scalars().all())


async def _can_read_group_table(
    rebac: "FastAPIReBAC[Any]",
    session: AsyncSession,
    actor: Any,
) -> bool:
    if getattr(actor, "is_superuser", False):
        return True

    return await rebac.get_access_manager(session).can(
        user=actor,
        action=Action.READ,
        table_key=str(Group.__tablename__),
    )


async def _visible_group_choices(
    rebac: "FastAPIReBAC[Any]",
    session: AsyncSession,
    actor: Any,
    *,
    exclude_group_ids: set[Any] | None = None,
) -> list[Group]:
    if getattr(actor, "is_superuser", False):
        stmt = select(Group)
    else:
        if not await _can_read_group_table(rebac, session, actor):
            return []
        stmt = await rebac.resolve_accessible_select(
            Group.created_by_id,
            user=actor,
            session=session,
        )
    if exclude_group_ids:
        stmt = stmt.where(Group.id.not_in(exclude_group_ids))
    stmt = stmt.order_by(Group.name)
    return list((await session.execute(stmt)).scalars().all())


def _filter_auth_tables_for_new_permissions(
    auth_tables: list[AuthTable],
    existing_permissions: list[UserPermission],
) -> list[AuthTable]:
    existing_actions_by_table: dict[Any, set[Action]] = {}
    for permission in existing_permissions:
        existing_actions_by_table.setdefault(permission.table_id, set()).add(permission.action)
    all_actions = set(Action)
    return [table for table in auth_tables if existing_actions_by_table.get(table.id, set()) != all_actions]


def _selected_or_manual(
    form: Any,
    select_name: str,
    manual_name: str,
    *,
    require_both: bool = False,
) -> str | None:
    selected = form.get(select_name)
    manual = form.get(manual_name)

    selected_value = selected.strip() if isinstance(selected, str) and selected.strip() else None
    manual_value = manual.strip() if isinstance(manual, str) and manual.strip() else None

    if require_both and (selected_value or manual_value):
        if not selected_value or not manual_value:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Choose a related object from the list and keep its ID filled in.",
            )
        if selected_value != manual_value:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Selected object and manual ID do not match.",
            )

    if manual_value and manual_value != selected_value:
        return manual_value
    if selected_value:
        return selected_value
    return manual_value


def _coerce_optional_user_pk(rebac: "FastAPIReBAC[Any]", raw_value: str | None) -> Any | None:
    if not raw_value:
        return None
    return _coerce_pk_value(rebac.user_model, "id", raw_value)


async def _ensure_user_exists(rebac: "FastAPIReBAC[Any]", session: AsyncSession, user_pk: Any | None) -> None:
    if user_pk is None:
        return
    if await session.get(rebac.user_model, user_pk) is None:
        raise HTTPException(status_code=400, detail="Selected user does not exist.")


async def _ensure_group_exists(session: AsyncSession, group_pk: Any | None) -> None:
    if group_pk is None:
        return
    if await session.get(Group, group_pk) is None:
        raise HTTPException(status_code=400, detail="Selected group does not exist.")


async def _ensure_auth_table_exists(session: AsyncSession, table_pk: Any | None) -> None:
    if table_pk is None:
        return
    if await session.get(AuthTable, table_pk) is None:
        raise HTTPException(status_code=400, detail="Selected table does not exist.")


async def _get_visible_group_or_404(
    rebac: "FastAPIReBAC[Any]",
    session: AsyncSession,
    actor: Any,
    group_pk: Any,
) -> Group:
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
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Group is not visible.")
    return group_obj


async def _ensure_can_manage_user_acl(
    rebac: "FastAPIReBAC[Any]",
    session: AsyncSession,
    actor: Any,
    user_id: str,
) -> Any:
    user_obj = await _get_visible_user_or_404(rebac, session, actor, user_id)
    if not await _can_admin_update_table(
        rebac, session, actor, str(getattr(rebac.user_model, "__tablename__", "user"))
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="UPDATE permission on the user table is required.",
        )
    return user_obj


def register_user_routes(router: APIRouter, rebac: "FastAPIReBAC[Any]") -> None:
    @router.get("/users", response_class=HTMLResponse, name="admin_users_page")
    async def admin_users_page(
        request: Request,
        actor=Depends(rebac.staff_required),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> HTMLResponse:
        if actor.is_superuser:
            user_stmt = select(rebac.user_model)
        else:
            user_stmt = await rebac.resolve_accessible_select(
                rebac.user_model.id,
                user=actor,
                session=session,
            )
        users = list((await session.execute(user_stmt)).scalars().all())
        auth_tables = await _visible_auth_tables_for_user(rebac, session, actor)
        groups = list((await session.execute(select(Group).order_by(Group.name))).scalars().all())

        user_rows = []
        for user_obj in users:
            user_rows.append(
                {
                    "obj": user_obj,
                    "created_by": await _display_value_for_model_pk(
                        rebac, session, request, rebac.user_model, user_obj.created_by_id
                    ) if getattr(user_obj, "created_by_id", None) is not None else None,
                    "supervisor": await _display_value_for_model_pk(
                        rebac, session, request, rebac.user_model, user_obj.supervisor_id
                    ) if getattr(user_obj, "supervisor_id", None) is not None else None,
                    "created_at": _format_scalar_value(getattr(user_obj, "created_at", None)),
                    "updated_at": _format_scalar_value(getattr(user_obj, "updated_at", None)),
                }
            )

        return rebac.templates.TemplateResponse(
            request=request,
            name="rebac_admin/users.html",
            context=await _with_admin_context(
                rebac,
                session,
                actor,
                {
                    "users": users,
                    "user_rows": user_rows,
                    "auth_tables": auth_tables,
                    "groups": groups,
                    "create_allowed": actor.is_superuser,
                },
            ),
        )

    @router.get("/users/create", response_class=HTMLResponse, name="admin_user_create_page")
    async def admin_user_create_page(
        request: Request,
        actor=Depends(rebac.superuser_required),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> HTMLResponse:
        return await _admin_template_response(
            rebac,
            request,
            session,
            actor,
            "rebac_admin/user_create.html",
            {"supervisor_choices": await _user_choices(rebac, session)},
            include_csrf=True,
        )

    @router.post("/users/create", name="admin_user_create_submit")
    async def admin_user_create_submit(
        request: Request,
        email: str = Form(...),
        username: str = Form(...),
        first_name: str | None = Form(None),
        last_name: str | None = Form(None),
        password: str = Form(...),
        is_active: bool = Form(False),
        is_superuser: bool = Form(False),
        is_staff: bool = Form(False),
        is_verified: bool = Form(False),
        actor=Depends(rebac.superuser_required),
        manager=Depends(rebac.user_manager_dependency),
        _csrf_protect: None = Depends(rebac.csrf_protect),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> RedirectResponse:
        form = await request.form()
        supervisor_raw = _selected_or_manual(form, "supervisor_id_select", "supervisor_id", require_both=True)
        supervisor_id = _coerce_optional_user_pk(rebac, supervisor_raw)
        await _ensure_user_exists(rebac, session, supervisor_id)

        await _ensure_unique_user_field(rebac, session, "email", email)
        await _ensure_unique_user_field(rebac, session, "username", username)

        payload = await manager.admin_prepare_create_dict(
            email=email,
            password=password,
            is_active=is_active,
            is_superuser=is_superuser,
            is_staff=is_staff,
            is_verified=is_verified,
            extra={
                "username": username,
                "first_name": first_name,
                "last_name": last_name,
                "created_by_id": actor.id,
                "supervisor_id": supervisor_id,
            },
        )

        user_obj = rebac.user_model(**payload)
        session.add(user_obj)
        await session.commit()
        await session.refresh(user_obj)
        await _log_admin_success(
            rebac,
            session,
            request,
            actor,
            action=Action.CREATE,
            table_key=str(getattr(rebac.user_model, "__tablename__", "user")),
            object_id=user_obj.id,
            meta={"email": user_obj.email, "username": user_obj.username},
        )

        return RedirectResponse(
            url=request.url_for("admin_user_detail_page", user_id=str(user_obj.id)),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @router.get("/users/{user_id}", response_class=HTMLResponse, name="admin_user_detail_page")
    async def admin_user_detail_page(
        request: Request,
        user_id: str,
        actor=Depends(rebac.staff_required),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> HTMLResponse:
        user_obj = await _get_visible_user_or_404(rebac, session, actor, user_id)
        user_pk = user_obj.id
        can_read_groups = await _can_read_group_table(rebac, session, actor)
        visible_groups = await _visible_group_choices(rebac, session, actor) if can_read_groups else []
        visible_group_ids = {group.id for group in visible_groups}
        memberships_stmt = select(GroupMembership).where(GroupMembership.user_id == user_pk)
        if not getattr(actor, "is_superuser", False):
            if visible_group_ids:
                memberships_stmt = memberships_stmt.where(GroupMembership.group_id.in_(visible_group_ids))
            else:
                memberships_stmt = memberships_stmt.where(false())
        memberships = list((await session.execute(memberships_stmt)).scalars().all())
        visible_auth_tables = await _visible_auth_tables_for_user(rebac, session, actor)
        visible_auth_table_ids = {table.id for table in visible_auth_tables}
        permissions_stmt = select(UserPermission).where(UserPermission.user_id == user_pk)
        if not getattr(actor, "is_superuser", False):
            permissions_stmt = permissions_stmt.where(UserPermission.table_id.in_(visible_auth_table_ids))
        permissions = list((await session.execute(permissions_stmt)).scalars().all())
        existing_group_ids = {membership.group_id for membership in memberships}
        groups = [
            group
            for group in visible_groups
            if group.id not in existing_group_ids
        ]
        auth_tables = _filter_auth_tables_for_new_permissions(visible_auth_tables, permissions)
        can_manage_user_acl = await _can_admin_update_table(
            rebac, session, actor, str(getattr(rebac.user_model, "__tablename__", "user"))
        )
        can_manage_user_groups = can_manage_user_acl and can_read_groups

        membership_rows = []
        for membership in memberships:
            membership_rows.append(
                {
                    "id": membership.id,
                    "group": await _display_value_for_model_pk(
                        rebac, session, request, Group, membership.group_id
                    ),
                    "created_by": await _display_value_for_model_pk(
                        rebac, session, request, rebac.user_model, membership.created_by_id
                    ) if membership.created_by_id is not None else None,
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
                    ) if permission.granted_by_id is not None else None,
                }
            )

        created_by_display = await _display_value_for_model_pk(
            rebac, session, request, rebac.user_model, user_obj.created_by_id
        ) if user_obj.created_by_id is not None else None
        supervisor_display = await _display_value_for_model_pk(
            rebac, session, request, rebac.user_model, user_obj.supervisor_id
        ) if user_obj.supervisor_id is not None else None

        return await _admin_template_response(
            rebac,
            request,
            session,
            actor,
            "rebac_admin/user_detail.html",
            {
                "user_obj": user_obj,
                "memberships": memberships,
                "permissions": permissions,
                "membership_rows": membership_rows,
                "permission_rows": permission_rows,
                "created_by_display": created_by_display,
                "supervisor_display": supervisor_display,
                "created_at_display": _format_scalar_value(getattr(user_obj, "created_at", None)),
                "updated_at_display": _format_scalar_value(getattr(user_obj, "updated_at", None)),
                "groups": groups,
                "auth_tables": auth_tables,
                "actions": list(Action),
                "can_update_user": actor.is_superuser,
                "can_delete_user": actor.is_superuser and actor.id != user_obj.id,
                "can_read_membership": can_manage_user_groups,
                "can_create_membership": can_manage_user_groups,
                "can_delete_membership": can_manage_user_groups,
                "can_read_permission": can_manage_user_acl,
                "can_create_permission": can_manage_user_acl,
                "can_delete_permission": can_manage_user_acl,
            },
            include_csrf=True,
        )

    @router.post("/users/{user_id}/groups/add", name="admin_user_add_group")
    async def admin_user_add_group(
        request: Request,
        user_id: str,
        actor=Depends(rebac.staff_required),
        _csrf_protect: None = Depends(rebac.csrf_protect),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> RedirectResponse:
        form = await request.form()
        group_raw = _selected_or_manual(form, "group_id_select", "group_id", require_both=True)
        if group_raw is None:
            raise HTTPException(status_code=400, detail="Group is required.")

        user_obj = await _ensure_can_manage_user_acl(rebac, session, actor, user_id)
        user_pk = user_obj.id
        group_pk = _coerce_pk_value(Group, "id", group_raw)
        await _get_visible_group_or_404(rebac, session, actor, group_pk)
        existing = await session.execute(
            select(GroupMembership).where(
                GroupMembership.user_id == user_pk,
                GroupMembership.group_id == group_pk,
            )
        )
        if existing.scalar_one_or_none() is None:
            membership = GroupMembership(user_id=user_pk, group_id=group_pk, created_by_id=actor.id)
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
                    "user_id": str(user_pk),
                    "group_id": str(group_pk),
                    "created_by_id": str(actor.id),
                    "source": "user_detail",
                },
            )

        return RedirectResponse(
            url=request.url_for("admin_user_detail_page", user_id=user_id),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @router.post("/users/{user_id}/groups/{membership_id}/delete", name="admin_user_remove_group")
    async def admin_user_remove_group(
        request: Request,
        user_id: str,
        membership_id: str,
        actor=Depends(rebac.staff_required),
        _csrf_protect: None = Depends(rebac.csrf_protect),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> RedirectResponse:
        user_obj = await _ensure_can_manage_user_acl(rebac, session, actor, user_id)
        user_pk = user_obj.id
        membership_pk = _coerce_pk_value(GroupMembership, "id", membership_id)
        membership = (
            await session.execute(
                select(GroupMembership).where(
                    GroupMembership.id == membership_pk,
                    GroupMembership.user_id == user_pk,
                )
            )
        ).scalar_one_or_none()
        if membership is not None:
            group_pk = membership.group_id
            created_by_pk = membership.created_by_id
            await _get_visible_group_or_404(rebac, session, actor, group_pk)
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
                    "user_id": str(user_pk),
                    "group_id": str(group_pk),
                    "created_by_id": str(created_by_pk),
                    "source": "user_detail",
                },
            )

        return RedirectResponse(
            url=request.url_for("admin_user_detail_page", user_id=user_id),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @router.post("/users/{user_id}/permissions/add", name="admin_user_add_permission")
    async def admin_user_add_permission(
        request: Request,
        user_id: str,
        action: str = Form(...),
        actor=Depends(rebac.staff_required),
        _csrf_protect: None = Depends(rebac.csrf_protect),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> RedirectResponse:
        form = await request.form()
        table_raw = _selected_or_manual(form, "table_id_select", "table_id", require_both=True)
        if table_raw is None:
            raise HTTPException(status_code=400, detail="Table is required.")

        user_obj = await _ensure_can_manage_user_acl(rebac, session, actor, user_id)
        user_pk = user_obj.id
        table_pk = _coerce_pk_value(AuthTable, "id", table_raw)
        await _ensure_auth_table_exists(session, table_pk)
        action_enum = _parse_action(action)
        if not await _can_admin_delegate_permission(rebac, session, actor, table_pk, action_enum):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You may grant only permissions that you have yourself.",
            )
        existing = await session.execute(
            select(UserPermission).where(
                UserPermission.user_id == user_pk,
                UserPermission.table_id == table_pk,
                UserPermission.action == action_enum,
            )
        )
        if existing.scalar_one_or_none() is None:
            permission = UserPermission(
                user_id=user_pk,
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
                table_key=str(UserPermission.__tablename__),
                object_id=permission.id,
                meta={
                    "user_id": str(user_pk),
                    "table_id": str(table_pk),
                    "permission_action": action_enum.value,
                },
            )

        return RedirectResponse(
            url=request.url_for("admin_user_detail_page", user_id=user_id),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @router.post("/users/{user_id}/permissions/{permission_id}/delete", name="admin_user_remove_permission")
    async def admin_user_remove_permission(
        request: Request,
        user_id: str,
        permission_id: str,
        actor=Depends(rebac.staff_required),
        _csrf_protect: None = Depends(rebac.csrf_protect),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> RedirectResponse:
        user_obj = await _ensure_can_manage_user_acl(rebac, session, actor, user_id)
        user_pk = user_obj.id
        permission_pk = _coerce_pk_value(UserPermission, "id", permission_id)
        permission = (
            await session.execute(
                select(UserPermission).where(
                    UserPermission.id == permission_pk,
                    UserPermission.user_id == user_pk,
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
                table_key=str(UserPermission.__tablename__),
                object_id=permission_pk,
                meta={
                    "user_id": str(user_pk),
                    "table_id": str(table_pk),
                    "permission_action": permission_action,
                },
            )

        return RedirectResponse(
            url=request.url_for("admin_user_detail_page", user_id=user_id),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @router.get("/users/{user_id}/edit", response_class=HTMLResponse, name="admin_user_edit_page")
    async def admin_user_edit_page(
        request: Request,
        user_id: str,
        actor=Depends(rebac.superuser_required),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> HTMLResponse:
        user_pk = _coerce_pk_value(rebac.user_model, "id", user_id)
        user_obj = await session.get(rebac.user_model, user_pk)
        if user_obj is None:
            raise HTTPException(status_code=404, detail="User not found.")

        return await _admin_template_response(
            rebac,
            request,
            session,
            actor,
            "rebac_admin/user_edit.html",
            {
                "user_obj": user_obj,
                "supervisor_choices": await _user_choices(rebac, session, exclude_user_id=user_pk),
            },
            include_csrf=True,
        )

    @router.post("/users/{user_id}/edit", name="admin_user_edit_submit")
    async def admin_user_edit_submit(
        request: Request,
        user_id: str,
        email: str = Form(...),
        username: str = Form(...),
        first_name: str | None = Form(None),
        last_name: str | None = Form(None),
        is_active: bool = Form(False),
        is_superuser: bool = Form(False),
        is_staff: bool = Form(False),
        is_verified: bool = Form(False),
        actor=Depends(rebac.superuser_required),
        manager=Depends(rebac.user_manager_dependency),
        _csrf_protect: None = Depends(rebac.csrf_protect),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> RedirectResponse:
        user_pk = _coerce_pk_value(rebac.user_model, "id", user_id)
        user_obj = await session.get(rebac.user_model, user_pk)
        if user_obj is None:
            raise HTTPException(status_code=404, detail="User not found.")

        form = await request.form()
        supervisor_raw = _selected_or_manual(form, "supervisor_id_select", "supervisor_id", require_both=True)
        supervisor_id = _coerce_optional_user_pk(rebac, supervisor_raw)
        if supervisor_id == user_pk:
            raise HTTPException(status_code=400, detail="User cannot supervise themself.")
        await _ensure_user_exists(rebac, session, supervisor_id)

        await _ensure_unique_user_field(rebac, session, "email", email, exclude_user_id=user_pk)
        await _ensure_unique_user_field(rebac, session, "username", username, exclude_user_id=user_pk)

        update_dict = await manager.admin_prepare_update_dict(
            user_obj,
            email=email,
            is_active=is_active,
            is_superuser=is_superuser,
            is_staff=is_staff,
            is_verified=is_verified,
            extra={
                "username": username,
                "first_name": first_name,
                "last_name": last_name,
                "supervisor_id": supervisor_id,
            },
        )
        await _user_manager_update_user(user_obj, update_dict)
        await session.commit()
        await _log_admin_success(
            rebac,
            session,
            request,
            actor,
            action=Action.UPDATE,
            table_key=str(getattr(rebac.user_model, "__tablename__", "user")),
            object_id=user_pk,
            meta={"email": user_obj.email, "username": user_obj.username},
        )

        return RedirectResponse(
            url=request.url_for("admin_user_detail_page", user_id=user_id),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @router.get("/users/{user_id}/password", response_class=HTMLResponse, name="admin_user_password_page")
    async def admin_user_password_page(
        request: Request,
        user_id: str,
        actor=Depends(rebac.superuser_required),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> HTMLResponse:
        user_pk = _coerce_pk_value(rebac.user_model, "id", user_id)
        user_obj = await session.get(rebac.user_model, user_pk)
        if user_obj is None:
            raise HTTPException(status_code=404, detail="User not found.")

        return await _admin_template_response(
            rebac,
            request,
            session,
            actor,
            "rebac_admin/user_password.html",
            {"user_obj": user_obj},
            include_csrf=True,
        )

    @router.post("/users/{user_id}/password", name="admin_user_password_submit")
    async def admin_user_password_submit(
        request: Request,
        user_id: str,
        password: str = Form(...),
        password_confirm: str = Form(...),
        actor=Depends(rebac.superuser_required),
        manager=Depends(rebac.user_manager_dependency),
        _csrf_protect: None = Depends(rebac.csrf_protect),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> RedirectResponse:
        if password != password_confirm:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Passwords do not match.",
            )

        user_pk = _coerce_pk_value(rebac.user_model, "id", user_id)
        user_obj = await session.get(rebac.user_model, user_pk)
        if user_obj is None:
            raise HTTPException(status_code=404, detail="User not found.")

        user_obj.hashed_password = await manager.admin_set_password(
            user_obj,
            password=password,
        )
        await session.commit()
        await _log_admin_success(
            rebac,
            session,
            request,
            actor,
            action=Action.UPDATE,
            table_key=str(getattr(rebac.user_model, "__tablename__", "user")),
            object_id=user_pk,
            meta={"operation": "change_password"},
        )

        return RedirectResponse(
            url=request.url_for("admin_user_detail_page", user_id=user_id),
            status_code=status.HTTP_303_SEE_OTHER,
        )

    @router.get("/users/{user_id}/delete", response_class=HTMLResponse, name="admin_user_delete_page")
    async def admin_user_delete_page(
        request: Request,
        user_id: str,
        actor=Depends(rebac.superuser_required),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> HTMLResponse:
        user_pk = _coerce_pk_value(rebac.user_model, "id", user_id)
        user_obj = await session.get(rebac.user_model, user_pk)
        if user_obj is None:
            raise HTTPException(status_code=404, detail="User not found.")

        return await _admin_template_response(
            rebac,
            request,
            session,
            actor,
            "rebac_admin/user_delete.html",
            {"user_obj": user_obj},
            include_csrf=True,
        )

    @router.post("/users/{user_id}/delete", name="admin_user_delete_submit")
    async def admin_user_delete_submit(
        request: Request,
        user_id: str,
        actor=Depends(rebac.superuser_required),
        _csrf_protect: None = Depends(rebac.csrf_protect),
        session: AsyncSession = Depends(rebac.session_dependency),
    ) -> RedirectResponse:
        user_pk = _coerce_pk_value(rebac.user_model, "id", user_id)
        if actor.id == user_pk:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="You cannot deactivate yourself.",
            )

        user_obj = await session.get(rebac.user_model, user_pk)
        if user_obj is None:
            raise HTTPException(status_code=404, detail="User not found.")

        user_obj.is_active = False
        await session.commit()
        await _log_admin_success(
            rebac,
            session,
            request,
            actor,
            action=Action.DELETE,
            table_key=str(getattr(rebac.user_model, "__tablename__", "user")),
            object_id=user_pk,
            meta={"operation": "deactivate", "email": user_obj.email},
        )

        return RedirectResponse(
            url=request.url_for("admin_users_page"),
            status_code=status.HTTP_303_SEE_OTHER,
        )
