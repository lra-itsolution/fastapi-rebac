from __future__ import annotations

import uuid
from datetime import date, datetime, time
from enum import Enum
from typing import Any, TYPE_CHECKING

from fastapi import HTTPException, Request, status
from fastapi.responses import HTMLResponse
from sqlalchemy import inspect, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..enums import Action
from ..errors import ConfigurationError
from ..models import AuthTable
from ..types import (
    AdminDisplayValue,
    AdminFormChoice,
    AdminFormField,
    AdminModelConfig,
    AdminResourceRow,
)

if TYPE_CHECKING:
    from ..fastapi_rebac import FastAPIReBAC


_RESOURCE_ADMIN_VIEW = "generic"
_FORM_EXCLUDE_ALWAYS = {"created_at", "updated_at"}
_LIBRARY_FORM_EXCLUDE_ALWAYS = {"created_by_id", "created_at", "updated_at"}
_DISPLAY_SERVICE_FIELDS = ("created_by_id", "created_at", "updated_at")


def _visible_auth_tables_query(rebac: "FastAPIReBAC[Any]"):
    query = select(AuthTable)
    hidden = rebac.hidden_admin_table_keys
    if hidden:
        query = query.where(AuthTable.key.not_in(hidden))
    return query.order_by(AuthTable.key)


def _coerce_value(raw: str | None, python_type: type[Any], *, checkbox_present: bool = False) -> Any:
    if python_type is bool:
        return checkbox_present

    if raw is None:
        return None

    raw = raw.strip()
    if raw == "":
        return None

    if python_type is str:
        return raw
    if python_type is int:
        return int(raw)
    if python_type is float:
        return float(raw)
    if python_type is uuid.UUID:
        return uuid.UUID(raw)
    if python_type is datetime:
        return datetime.fromisoformat(raw)
    if python_type is date:
        return date.fromisoformat(raw)
    if python_type is time:
        return time.fromisoformat(raw)

    return raw


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


def _coerce_pk_value(model: type[Any], pk_attr_name: str, raw_value: str) -> Any:
    pk_attr = getattr(model, pk_attr_name)
    column = pk_attr.property.columns[0]
    try:
        python_type = column.type.python_type
    except Exception:
        return raw_value

    try:
        coerced = _coerce_value(raw_value, python_type)
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Object not found.") from exc

    return raw_value if coerced is None else coerced


def _admin_model_config_or_404(
    rebac: "FastAPIReBAC[Any]",
    table_key: str,
) -> AdminModelConfig:
    try:
        config = rebac.get_admin_model_config(table_key)
    except ConfigurationError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found.") from exc

    if config["hidden"]:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found.")

    return config


def _is_resource_admin_model(config: AdminModelConfig) -> bool:
    return bool(config["admin_view"] == _RESOURCE_ADMIN_VIEW and not config["hidden"])


def _available_resource_configs(
    rebac: "FastAPIReBAC[Any]",
    user: Any,
    allowed_tables: set[str],
) -> list[AdminModelConfig]:
    """Return only user-defined generic resources, not dedicated administration sections."""

    return [
        item
        for item in rebac.get_registered_admin_models()
        if _is_resource_admin_model(item)
        and (getattr(user, "is_superuser", False) or item["table_key"] in allowed_tables)
    ]


async def _admin_nav_context(
    rebac: "FastAPIReBAC[Any]",
    session: AsyncSession,
    user: Any,
) -> dict[str, Any]:
    read_keys = await _allowed_table_keys(rebac, session, user, "READ")
    resources = _available_resource_configs(rebac, user, read_keys)

    def can_read(table_key: str) -> bool:
        return bool(getattr(user, "is_superuser", False) or table_key in read_keys)

    return {
        "can_read_resources": bool(resources),
        "can_read_users": can_read(str(getattr(rebac.user_model, "__tablename__", "user"))),
        "can_read_groups": can_read("group"),
        "can_read_auth_tables": can_read("auth_table"),
        "can_read_audit_logs": can_read("audit_log"),
        "can_read_suspicious_alerts": can_read("suspicious_alert"),
        "resources": resources,
    }


async def _with_admin_context(
    rebac: "FastAPIReBAC[Any]",
    session: AsyncSession,
    user: Any,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    template_context = dict(context or {})
    template_context.setdefault("user", user)
    template_context.setdefault("actor", user)
    template_context.setdefault("admin_nav", await _admin_nav_context(rebac, session, user))
    return template_context


async def _admin_template_response(
    rebac: "FastAPIReBAC[Any]",
    request: Request,
    session: AsyncSession,
    user: Any,
    name: str,
    context: dict[str, Any] | None = None,
    *,
    include_csrf: bool = False,
) -> HTMLResponse:
    return _template_response(
        rebac,
        request,
        name,
        await _with_admin_context(rebac, session, user, context),
        include_csrf=include_csrf,
    )


async def _log_admin_success(
    rebac: "FastAPIReBAC[Any]",
    session: AsyncSession,
    request: Request,
    actor: Any,
    *,
    action: Action,
    table_key: str,
    object_id: Any | None = None,
    meta: dict[str, Any] | None = None,
) -> None:
    await rebac.get_audit_manager(session).log_success(
        action=action,
        actor=actor,
        table_key=table_key,
        object_id=object_id,
        request=request,
        meta=meta,
    )


def _template_response(
    rebac: "FastAPIReBAC[Any]",
    request: Request,
    name: str,
    context: dict[str, Any] | None = None,
    *,
    include_csrf: bool = False,
) -> HTMLResponse:
    template_context = dict(context or {})
    csrf_token: str | None = None

    if include_csrf:
        csrf_token = rebac.csrf.get_or_create_token(request)
        template_context["csrf_token"] = csrf_token

    response = rebac.templates.TemplateResponse(
        request=request,
        name=name,
        context=template_context,
    )

    if include_csrf and csrf_token is not None and rebac.csrf.needs_cookie_refresh(request):
        rebac.csrf.set_cookie(response, csrf_token)

    return response


def _column_input_type(column: Any) -> str:
    if _is_foreign_key_column(column):
        return "foreign_key"

    try:
        py = column.type.python_type
    except Exception:
        py = str

    if py is bool:
        return "checkbox"
    if py is int:
        return "number"
    if py is float:
        return "number"
    if py is datetime:
        return "datetime-local"
    if py is date:
        return "date"
    if py is time:
        return "time"
    return "text"


def _iter_scalar_columns(model: type[Any]) -> list[Any]:
    mapper = inspect(model)
    return list(mapper.columns)


def _is_foreign_key_column(column: Any) -> bool:
    return bool(getattr(column, "foreign_keys", None))


def _first_foreign_key(column: Any) -> Any | None:
    foreign_keys = list(getattr(column, "foreign_keys", []) or [])
    return foreign_keys[0] if foreign_keys else None


def _format_scalar_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, Enum):
        return str(value.value)
    if isinstance(value, datetime):
        return value.replace(microsecond=0).isoformat(sep=" ", timespec="minutes")
    if isinstance(value, (date, time)):
        return value.isoformat()
    return str(value)


def _format_form_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.replace(microsecond=0).isoformat(timespec="minutes")
    if isinstance(value, (date, time)):
        return value.isoformat()
    return value


def _object_label(obj: Any, fallback: Any = None) -> str:
    if obj is None:
        return _format_scalar_value(fallback)

    label = str(obj)
    # A model without __str__ gives '<module.Model object at 0x...>', which is not useful in admin UI.
    if label.startswith("<") and " object at " in label:
        for attr in ("name", "title", "username", "email", "key"):
            value = getattr(obj, attr, None)
            if value:
                return str(value)
        obj_id = getattr(obj, "id", fallback)
        return _format_scalar_value(obj_id)
    return label


def _admin_object_url(request: Request, config: AdminModelConfig, object_id: Any) -> str | None:
    if object_id is None or config["hidden"]:
        return None

    view = config["admin_view"]
    try:
        if view == "user":
            return str(request.url_for("admin_user_detail_page", user_id=str(object_id)))
        if view == "group":
            return str(request.url_for("admin_group_detail_page", group_id=str(object_id)))
        if view == "auth_table":
            # Auth tables have a dedicated list page, but the generic object route is still valid.
            return str(
                request.url_for(
                    "admin_resource_detail_page",
                    table_key=config["table_key"],
                    object_id=str(object_id),
                )
            )
        if view == "suspicious_alert":
            return str(
                request.url_for(
                    "admin_resource_detail_page",
                    table_key=config["table_key"],
                    object_id=str(object_id),
                )
            )
        if view == _RESOURCE_ADMIN_VIEW:
            return str(
                request.url_for(
                    "admin_resource_detail_page",
                    table_key=config["table_key"],
                    object_id=str(object_id),
                )
            )
    except Exception:
        return None
    return None


def _display_value(label: Any, *, raw: Any = None, url: str | None = None, is_foreign_key: bool = False) -> AdminDisplayValue:
    return {
        "label": _format_scalar_value(label),
        "raw": raw,
        "url": url,
        "is_foreign_key": is_foreign_key,
    }


def _target_config_for_fk(rebac: "FastAPIReBAC[Any]", column: Any) -> tuple[AdminModelConfig, Any] | None:
    fk = _first_foreign_key(column)
    if fk is None:
        return None

    target_column = fk.column
    target_table_key = str(target_column.table.name)
    try:
        return rebac.get_admin_model_config(target_table_key), target_column
    except ConfigurationError:
        return None


async def _load_fk_target(
    rebac: "FastAPIReBAC[Any]",
    session: AsyncSession,
    column: Any,
    value: Any,
) -> tuple[AdminModelConfig, Any, Any] | None:
    if value is None:
        return None

    target_info = _target_config_for_fk(rebac, column)
    if target_info is None:
        return None

    target_config, target_column = target_info
    target_model = target_config["model"]
    result = await session.execute(select(target_model).where(target_column == value))
    target_obj = result.scalar_one_or_none()
    return target_config, target_column, target_obj


async def _assert_fk_target_exists(
    rebac: "FastAPIReBAC[Any]",
    session: AsyncSession,
    column: Any,
    value: Any,
    *,
    field_name: str,
) -> None:
    if value is None or not _is_foreign_key_column(column):
        return

    fk_target = await _load_fk_target(rebac, session, column, value)
    if fk_target is None:
        # The FK target table is not registered in the admin. Let the database enforce it.
        return

    _target_config, _target_column, target_obj = fk_target
    if target_obj is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Related object for field {field_name!r} does not exist.",
        )


async def _display_value_for_column(
    rebac: "FastAPIReBAC[Any]",
    session: AsyncSession,
    request: Request,
    column: Any,
    value: Any,
) -> AdminDisplayValue:
    if value is None:
        return _display_value("", raw=value, is_foreign_key=_is_foreign_key_column(column))

    if not _is_foreign_key_column(column):
        return _display_value(_format_scalar_value(value), raw=value)

    fk_target = await _load_fk_target(rebac, session, column, value)
    if fk_target is None:
        return _display_value(_format_scalar_value(value), raw=value, is_foreign_key=True)

    target_config, _target_column, target_obj = fk_target
    target_pk = getattr(target_obj, target_config["pk_attr_name"], value) if target_obj is not None else value
    return _display_value(
        _object_label(target_obj, fallback=value),
        raw=value,
        url=_admin_object_url(request, target_config, target_pk),
        is_foreign_key=True,
    )


async def _display_value_for_object(
    request: Request,
    obj: Any | None,
    config: AdminModelConfig,
    fallback: Any = None,
) -> AdminDisplayValue:
    object_id = getattr(obj, config["pk_attr_name"], fallback) if obj is not None else fallback
    return _display_value(
        _object_label(obj, fallback=fallback),
        raw=object_id,
        url=_admin_object_url(request, config, object_id),
        is_foreign_key=True,
    )


async def _display_value_for_model_pk(
    rebac: "FastAPIReBAC[Any]",
    session: AsyncSession,
    request: Request,
    model: type[Any],
    object_id: Any,
    *,
    table_key: str | None = None,
) -> AdminDisplayValue:
    resolved_table_key = table_key or str(getattr(model, "__tablename__", ""))
    try:
        config = rebac.get_admin_model_config(resolved_table_key)
    except ConfigurationError:
        return _display_value(object_id, raw=object_id, is_foreign_key=True)

    obj = await session.get(model, object_id) if object_id is not None else None
    return await _display_value_for_object(request, obj, config, fallback=object_id)


async def _fk_choices_for_column(
    rebac: "FastAPIReBAC[Any]",
    session: AsyncSession,
    request: Request,
    column: Any,
    *,
    limit: int = 200,
) -> list[AdminFormChoice]:
    target_info = _target_config_for_fk(rebac, column)
    if target_info is None:
        return []

    target_config, target_column = target_info
    target_model = target_config["model"]
    target_pk_attr = getattr(target_model, target_config["pk_attr_name"])
    stmt = select(target_model).order_by(target_pk_attr).limit(limit)
    rows = list((await session.execute(stmt)).scalars().all())

    choices: list[AdminFormChoice] = []
    for obj in rows:
        raw_value = getattr(obj, target_column.key)
        object_id = getattr(obj, target_config["pk_attr_name"])
        choices.append(
            {
                "value": str(raw_value),
                "label": _object_label(obj, fallback=raw_value),
                "url": _admin_object_url(request, target_config, object_id),
            }
        )
    return choices


async def _allowed_table_keys(
    rebac: "FastAPIReBAC[Any]",
    session: AsyncSession,
    user: Any,
    action: str,
) -> set[str]:
    access_manager = rebac.get_access_manager(session)
    return set(
        await access_manager.get_allowed_table_keys(
            user=user,
            action=action,
            exclude_hidden=True,
        )
    )


async def _assert_table_permission(
    rebac: "FastAPIReBAC[Any]",
    session: AsyncSession,
    user: Any,
    table_key: str,
    action: Action | str,
) -> None:
    config = _admin_model_config_or_404(rebac, table_key)
    if getattr(user, "is_superuser", False):
        return

    await rebac.resolve_require(
        action,
        config["model"],
        user=user,
        session=session,
    )


async def _resource_select(
    rebac: "FastAPIReBAC[Any]",
    session: AsyncSession,
    user: Any,
    config: AdminModelConfig,
) -> Any:
    model = config["model"]
    user_ref_attr = config.get("user_ref_attr")

    if user_ref_attr is not None:
        if getattr(user, "is_superuser", False):
            return select(model)
        return await rebac.resolve_accessible_select(
            user_ref_attr,
            user=user,
            session=session,
        )

    await _assert_table_permission(rebac, session, user, config["table_key"], Action.READ)
    return select(model)


async def _resource_object(
    rebac: "FastAPIReBAC[Any]",
    session: AsyncSession,
    user: Any,
    config: AdminModelConfig,
    object_id: str,
    *,
    action: Action | str = Action.READ,
) -> Any:
    model = config["model"]
    pk_attr_name = config["pk_attr_name"]
    coerced_object_id = _coerce_pk_value(model, pk_attr_name, object_id)
    user_ref_attr = config.get("user_ref_attr")

    if user_ref_attr is not None:
        if getattr(user, "is_superuser", False):
            result = await session.execute(select(model).where(getattr(model, pk_attr_name) == coerced_object_id))
            return result.scalar_one_or_none()
        return await rebac.resolve_require_object(
            action,
            user_ref_attr,
            coerced_object_id,
            user=user,
            session=session,
        )

    await _assert_table_permission(rebac, session, user, config["table_key"], action)
    result = await session.execute(select(model).where(getattr(model, pk_attr_name) == coerced_object_id))
    return result.scalar_one_or_none()


async def _apply_form_to_instance(
    rebac: "FastAPIReBAC[Any]",
    request: Request,
    session: AsyncSession,
    instance: Any,
    config: AdminModelConfig,
    *,
    for_create: bool,
    owner_user_id: Any | None = None,
) -> None:
    form = await request.form()
    fields = await _resource_form_fields(rebac, session, request, config, instance=instance, for_create=for_create)
    user_ref_attr = config.get("user_ref_attr")
    user_ref_column = rebac_user_ref_column_name(user_ref_attr) if user_ref_attr is not None else None
    user_ref_value_set = False

    for field in fields:
        if field["readonly"]:
            continue

        name = field["name"]
        column = field["column"]
        input_type = field["input_type"]

        if input_type == "foreign_key":
            raw = _selected_or_manual(
                form,
                f"{name}__select",
                name,
                require_both=bool(field["choices"]),
            )
        else:
            raw = form.get(name)

        is_missing = raw is None or (isinstance(raw, str) and not raw.strip())
        auto_owner_allowed = bool(for_create and owner_user_id is not None and user_ref_column is not None and name == user_ref_column)
        if field["required"] and is_missing and not auto_owner_allowed:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Field {name!r} is required.",
            )
        if is_missing and auto_owner_allowed:
            continue

        checkbox_present = name in form if input_type == "checkbox" else False

        try:
            python_type = column.type.python_type
        except Exception:
            python_type = str

        try:
            value = _coerce_value(raw if isinstance(raw, str) else None, python_type, checkbox_present=checkbox_present)
        except (TypeError, ValueError) as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid value for field {name!r}.",
            ) from exc

        if input_type == "foreign_key":
            await _assert_fk_target_exists(
                rebac,
                session,
                column,
                value,
                field_name=name,
            )

        setattr(instance, name, value)
        if user_ref_column is not None and name == user_ref_column and value is not None:
            user_ref_value_set = True

    if for_create and owner_user_id is not None and user_ref_column is not None and not user_ref_value_set:
        setattr(instance, user_ref_column, owner_user_id)


def rebac_user_ref_column_name(user_ref_attr: Any) -> str:
    from ..managers.access_manager import AccessManager

    return str(AccessManager.resolve_user_ref_column(user_ref_attr).key)


async def _resource_form_fields(
    rebac: "FastAPIReBAC[Any]",
    session: AsyncSession,
    request: Request,
    config: AdminModelConfig,
    instance: Any | None = None,
    *,
    for_create: bool = False,
) -> list[AdminFormField]:
    model = config["model"]
    pk_attr_name = config["pk_attr_name"]
    form_exclude: set[str] = set(config["form_exclude"]) | set(_FORM_EXCLUDE_ALWAYS)
    readonly_fields: set[str] = set(config["readonly_fields"])

    table_key = config["table_key"]
    if table_key in rebac.library_admin_table_keys:
        form_exclude |= set(_LIBRARY_FORM_EXCLUDE_ALWAYS)

    user_ref_attr = config.get("user_ref_attr")
    user_ref_column_name = rebac_user_ref_column_name(user_ref_attr) if user_ref_attr is not None else None
    if user_ref_column_name is not None and table_key in rebac.library_admin_table_keys:
        form_exclude.add(user_ref_column_name)

    items: list[AdminFormField] = []
    for column in _iter_scalar_columns(model):
        name = column.key
        if name in form_exclude:
            continue

        if for_create and name == pk_attr_name and column.primary_key:
            continue

        readonly = name in readonly_fields
        if not for_create and name == pk_attr_name:
            readonly = True

        value = getattr(instance, name, None) if instance is not None else None
        input_type = _column_input_type(column)
        choices = await _fk_choices_for_column(rebac, session, request, column) if input_type == "foreign_key" else []
        display = await _display_value_for_column(rebac, session, request, column, value)
        if input_type == "foreign_key" and value is not None and not any(choice["value"] == str(value) for choice in choices):
            fk_target = await _load_fk_target(rebac, session, column, value)
            if fk_target is not None:
                target_config, _target_column, target_obj = fk_target
                if target_obj is not None:
                    target_pk = getattr(target_obj, target_config["pk_attr_name"], value)
                    choices.append(
                        {
                            "value": str(value),
                            "label": _object_label(target_obj, fallback=value),
                            "url": _admin_object_url(request, target_config, target_pk),
                        }
                    )

        required = not column.nullable and not column.primary_key and input_type != "checkbox"
        if (
            for_create
            and user_ref_column_name is not None
            and name == user_ref_column_name
            and table_key in rebac.library_admin_table_keys
        ):
            # Library-owned resources can use the current user as the default owner.
            # User-defined resources must choose the FK explicitly unless nullable.
            required = False

        items.append(
            {
                "name": name,
                "label": name.replace("_", " ").title(),
                "required": required,
                "readonly": readonly,
                "input_type": input_type,
                "value": _format_form_value(value),
                "column": column,
                "is_foreign_key": input_type == "foreign_key",
                "choices": choices,
                "display": display,
            }
        )

    return items


async def _resource_display_fields(
    rebac: "FastAPIReBAC[Any]",
    session: AsyncSession,
    request: Request,
    config: AdminModelConfig,
    instance: Any,
) -> list[AdminFormField]:
    model = config["model"]
    items: list[AdminFormField] = []

    for column in _iter_scalar_columns(model):
        name = column.key
        if name in set(config["form_exclude"]):
            continue

        value = getattr(instance, name, None)
        input_type = _column_input_type(column)
        display = await _display_value_for_column(rebac, session, request, column, value)
        items.append(
            {
                "name": name,
                "label": name.replace("_", " ").title(),
                "required": False,
                "readonly": True,
                "input_type": input_type,
                "value": _format_form_value(value),
                "column": column,
                "is_foreign_key": input_type == "foreign_key",
                "choices": [],
                "display": display,
            }
        )
    return items


async def _resource_rows_context(
    rebac: "FastAPIReBAC[Any]",
    session: AsyncSession,
    request: Request,
    config: AdminModelConfig,
    rows: list[Any],
) -> list[AdminResourceRow]:
    display_fields: tuple[str, ...] = tuple(config["list_display"])
    pk_attr_name: str = config["pk_attr_name"]

    model = config["model"]
    columns_by_name = {column.key: column for column in _iter_scalar_columns(model)}

    if not display_fields:
        display_fields = (pk_attr_name,)

    display_field_list = list(display_fields)
    for service_field in _DISPLAY_SERVICE_FIELDS:
        if service_field in columns_by_name and service_field not in display_field_list:
            display_field_list.append(service_field)
    display_fields = tuple(display_field_list)

    items: list[AdminResourceRow] = []
    for row in rows:
        cells: list[tuple[str, AdminDisplayValue]] = []
        for field in display_fields:
            value = getattr(row, field, None)
            column = columns_by_name.get(field)
            if column is not None:
                display = await _display_value_for_column(rebac, session, request, column, value)
            else:
                display = _display_value(_format_scalar_value(value), raw=value)
            cells.append((field, display))
        items.append(
            {
                "pk": getattr(row, pk_attr_name),
                "cells": cells,
            }
        )
    return items


def _parse_action(raw_action: str) -> Action:
    try:
        if raw_action in Action.__members__:
            return Action[raw_action]
        return Action(raw_action)
    except (KeyError, ValueError) as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid action.") from exc


async def _user_manager_update_user(instance: Any, update_dict: dict[str, Any]) -> None:
    for key, value in update_dict.items():
        setattr(instance, key, value)
