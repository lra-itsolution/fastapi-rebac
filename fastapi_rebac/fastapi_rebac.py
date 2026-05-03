from __future__ import annotations

import contextvars
import secrets
from collections.abc import AsyncGenerator, Sequence
from pathlib import Path
from typing import Any, Generic, TypeVar, cast

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi_users import FastAPIUsers
from fastapi_users.authentication import AuthenticationBackend
from fastapi_users.manager import UserManagerDependency
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from . import schemas
from .access import BaseAccessController, SQLAlchemyAccessController
from .admin import build_admin_router
from .csrf import CSRFManager
from .enums import Action
from .errors import ConfigurationError
from .anomaly import SuspiciousActivityConfig
from .managers.access_manager import AccessManager
from .managers.audit_manager import AuditManager, normalize_audit_actions
from .models import (
    AuditLog,
    AuthTable,
    Group,
    GroupMembership,
    GroupPermission,
    ReBACBaseUser,
    SuspiciousAlert,
    User,
    UserPermission,
)
from .types import (
    ActionInput,
    AdminModelConfig,
    BackendName,
    CurrentUserDependency,
    EnabledBackendsDependency,
    CSRFProtectDependency,
    DependencyCallable,
    ObjectId,
    SelectStatement,
    SessionDependency,
    TableKey,
    TableRef,
    UserId,
    UserRefAttribute,
)

_UserT = TypeVar("_UserT", bound=ReBACBaseUser)



class FastAPIReBAC(Generic[_UserT]):
    def __init__(
        self,
        get_user_manager: UserManagerDependency,
        auth_backends: Sequence[AuthenticationBackend[_UserT, UserId]],
        *,
        get_async_session: SessionDependency,
        user_model: type[_UserT] = User,
        access_controller_class: type[BaseAccessController[_UserT]] | None = None,
        admin_templates: Jinja2Templates | None = None,
        csrf_secret: str | None = None,
        csrf_cookie_name: str = "rebac_csrf_token",
        csrf_cookie_secure: bool = True,
        audit_enabled: bool = True,
        audit_actions: Sequence[Action | str] | None = None,
        suspicious_activity_config: SuspiciousActivityConfig | None = None,
    ) -> None:
        if not auth_backends:
            raise ConfigurationError("'auth_backends' must not be empty.")

        if not issubclass(user_model, ReBACBaseUser):
            raise ConfigurationError(
                "'user_model' must inherit from fastapi_rebac.models.ReBACBaseUser."
            )

        user_table_name = getattr(user_model, "__tablename__", None)
        if user_table_name != "user":
            raise ConfigurationError(
                "FastAPIReBAC currently requires the user model table name to be 'user'. "
                "Internal authorization models use fixed foreign keys to 'user.id'."
            )

        self._user_model = user_model
        self._get_user_manager = get_user_manager
        self._auth_backends = tuple(auth_backends)
        self._get_async_session = get_async_session
        self._audit_enabled = audit_enabled
        self._audit_actions = normalize_audit_actions(audit_actions)
        self._suspicious_activity_config = suspicious_activity_config or SuspiciousActivityConfig()

        self._auth_backends_by_name: dict[BackendName, AuthenticationBackend[_UserT, UserId]] = {}
        self._current_user_cache: dict[
            tuple[bool, bool, bool, bool, bool, int | None],
            CurrentUserDependency,
        ] = {}
        self._current_user_context: contextvars.ContextVar[_UserT | None] = contextvars.ContextVar(
            "rebac_current_user",
            default=None,
        )
        self._current_session_context: contextvars.ContextVar[AsyncSession | None] = contextvars.ContextVar(
            "rebac_current_session",
            default=None,
        )

        self._hidden_admin_table_keys: set[TableKey] = {
            "group_membership",
            "group_permission",
            "user_permission",
        }
        self._library_admin_table_keys: set[TableKey] = {
            str(getattr(self._user_model, "__tablename__", "user")),
            str(Group.__tablename__),
            str(AuthTable.__tablename__),
            str(AuditLog.__tablename__),
            str(GroupMembership.__tablename__),
            str(GroupPermission.__tablename__),
            str(UserPermission.__tablename__),
            str(SuspiciousAlert.__tablename__),
        }
        self._admin_model_registry: dict[TableKey, AdminModelConfig] = {}

        for backend in self._auth_backends:
            backend_name = getattr(backend, "name", None)
            if not backend_name:
                raise ConfigurationError(
                    "Each authentication backend must have a non-empty 'name'."
                )
            if backend_name in self._auth_backends_by_name:
                raise ConfigurationError(
                    f"Duplicate authentication backend name: {backend_name!r}."
                )
            self._auth_backends_by_name[backend_name] = backend

        self._fastapi_users: FastAPIUsers[_UserT, UserId] = FastAPIUsers[_UserT, UserId](
            self._get_user_manager,
            self._auth_backends,
        )

        if admin_templates is None:
            templates_dir = Path(__file__).resolve().parent / "templates"
            admin_templates = Jinja2Templates(directory=str(templates_dir))
        self._admin_templates = admin_templates

        self._csrf = CSRFManager(
            secret_key=csrf_secret or secrets.token_urlsafe(32),
            cookie_name=csrf_cookie_name,
            cookie_secure=csrf_cookie_secure,
        )

        resolved_access_controller_class = access_controller_class or cast(
            type[BaseAccessController[_UserT]],
            SQLAlchemyAccessController,
        )
        self.access: BaseAccessController[_UserT] = resolved_access_controller_class(self)
        self._register_default_admin_models()

    def _register_default_admin_models(self) -> None:
        self.register_admin_model(
            self._user_model,
            title="Users",
            admin_view="user",
            form_exclude={"hashed_password"},
            readonly_fields={"created_at", "updated_at", "created_by_id", "supervisor_id"},
            list_display=("id", "email", "is_active", "is_superuser", "is_staff"),
            allow_create=False,
            allow_update=False,
            allow_delete=False,
        )
        self.register_admin_model(
            Group,
            title="Groups",
            admin_view="group",
            user_ref_attr=Group.created_by_id,
            readonly_fields={"created_at", "updated_at", "created_by_id"},
            list_display=(
                "id",
                "name",
                "share_members_visibility",
                "share_creator_visibility",
            ),
        )
        self.register_admin_model(
            AuthTable,
            title="Auth tables",
            admin_view="auth_table",
            readonly_fields={"created_at", "updated_at"},
            list_display=("id", "key", "title", "is_service"),
            allow_create=False,
            allow_delete=False,
        )
        self.register_admin_model(
            AuditLog,
            title="Audit logs",
            admin_view="audit_log",
            readonly_fields={
                "id",
                "created_at",
                "updated_at",
                "actor_id",
                "action",
                "table_key",
                "object_id",
                "status",
                "client_ip",
                "user_agent",
                "request_id",
                "meta",
            },
            list_display=(
                "created_at",
                "actor_id",
                "action",
                "table_key",
                "object_id",
                "status",
            ),
            allow_create=False,
            allow_update=False,
            allow_delete=False,
        )

        self.register_admin_model(
            SuspiciousAlert,
            title="Suspicious alerts",
            admin_view="suspicious_alert",
            readonly_fields={
                "id",
                "created_at",
                "updated_at",
                "actor_id",
                "detector_type",
                "rule_key",
                "severity",
                "score",
                "status",
                "description",
                "window_start",
                "window_end",
                "audit_log_ids",
                "payload",
            },
            list_display=(
                "created_at",
                "actor_id",
                "detector_type",
                "rule_key",
                "severity",
                "score",
                "status",
            ),
            allow_create=False,
            allow_update=False,
            allow_delete=False,
        )

        self.register_admin_model(GroupMembership, title="Group memberships", hidden=True)
        self.register_admin_model(GroupPermission, title="Group permissions", hidden=True)
        self.register_admin_model(UserPermission, title="User permissions", hidden=True)

    @property
    def session_dependency(self) -> SessionDependency:
        async def dependency() -> AsyncGenerator[AsyncSession, None]:
            async for session in self._get_async_session():
                token = self._current_session_context.set(session)
                try:
                    yield session
                finally:
                    self._current_session_context.reset(token)

        return dependency

    @property
    def user_manager_dependency(self) -> UserManagerDependency:
        return self._get_user_manager

    @property
    def auth_backends(self) -> tuple[AuthenticationBackend[_UserT, UserId], ...]:
        return self._auth_backends

    @property
    def csrf(self) -> CSRFManager:
        return self._csrf

    @property
    def csrf_protect(self) -> CSRFProtectDependency:
        return self._csrf.protect

    @property
    def templates(self) -> Jinja2Templates:
        return self._admin_templates

    @property
    def user_model(self) -> type[_UserT]:
        return self._user_model

    @property
    def hidden_admin_table_keys(self) -> set[TableKey]:
        return set(self._hidden_admin_table_keys)

    @property
    def library_admin_table_keys(self) -> set[TableKey]:
        return set(self._library_admin_table_keys)

    @property
    def audit_enabled(self) -> bool:
        return self._audit_enabled

    @property
    def audit_actions(self) -> frozenset[Action]:
        return self._audit_actions

    @property
    def suspicious_activity_config(self) -> SuspiciousActivityConfig:
        return self._suspicious_activity_config

    def get_audit_manager(self, session: AsyncSession) -> AuditManager:
        return AuditManager(
            session,
            enabled=self._audit_enabled,
            actions=self._audit_actions,
        )

    def register_admin_model(
        self,
        model: type[Any],
        *,
        title: str | None = None,
        hidden: bool = False,
        admin_view: str = "generic",
        pk_attr_name: str = "id",
        user_ref_attr: UserRefAttribute | None = None,
        form_exclude: set[str] | None = None,
        readonly_fields: set[str] | None = None,
        list_display: tuple[str, ...] | None = None,
        allow_create: bool = True,
        allow_update: bool = True,
        allow_delete: bool = True,
    ) -> None:
        table_key = getattr(model, "__tablename__", None)
        if not table_key:
            raise ConfigurationError(
                f"Could not register admin model without __tablename__: {model!r}."
            )

        normalized_table_key = str(table_key)
        form_exclude_set = set(form_exclude or set())
        readonly_fields_set = set(readonly_fields or set())

        if normalized_table_key in self._library_admin_table_keys and hasattr(model, "created_by_id"):
            readonly_fields_set.add("created_by_id")

        self._admin_model_registry[normalized_table_key] = {
            "table_key": normalized_table_key,
            "model": model,
            "title": title or normalized_table_key,
            "hidden": hidden,
            "admin_view": admin_view,
            "pk_attr_name": pk_attr_name,
            "user_ref_attr": user_ref_attr,
            "form_exclude": form_exclude_set,
            "readonly_fields": readonly_fields_set,
            "list_display": tuple(list_display or tuple()),
            "allow_create": allow_create,
            "allow_update": allow_update,
            "allow_delete": allow_delete,
        }

        if hidden:
            self._hidden_admin_table_keys.add(normalized_table_key)
        else:
            self._hidden_admin_table_keys.discard(normalized_table_key)

    def register_admin_models(self, *models: type[Any]) -> None:
        for model in models:
            self.register_admin_model(model)

    def get_registered_admin_models(self, *, include_hidden: bool = False) -> list[AdminModelConfig]:
        items: list[AdminModelConfig] = []
        for config in self._admin_model_registry.values():
            if not include_hidden and config["hidden"]:
                continue
            items.append(
                {
                    "table_key": config["table_key"],
                    "model": config["model"],
                    "title": config["title"],
                    "hidden": config["hidden"],
                    "admin_view": config["admin_view"],
                    "pk_attr_name": config["pk_attr_name"],
                    "user_ref_attr": config["user_ref_attr"],
                    "form_exclude": set(config["form_exclude"]),
                    "readonly_fields": set(config["readonly_fields"]),
                    "list_display": tuple(config["list_display"]),
                    "allow_create": bool(config["allow_create"]),
                    "allow_update": bool(config["allow_update"]),
                    "allow_delete": bool(config["allow_delete"]),
                }
            )
        items.sort(key=lambda item: item["title"].lower())
        return items

    def get_admin_model_config(self, table_key: TableKey) -> AdminModelConfig:
        try:
            config = self._admin_model_registry[table_key]
        except KeyError as exc:
            raise ConfigurationError(f"Admin model is not registered: {table_key!r}.") from exc

        return {
            "table_key": config["table_key"],
            "model": config["model"],
            "title": config["title"],
            "hidden": config["hidden"],
            "admin_view": config["admin_view"],
            "pk_attr_name": config["pk_attr_name"],
            "user_ref_attr": config["user_ref_attr"],
            "form_exclude": set(config["form_exclude"]),
            "readonly_fields": set(config["readonly_fields"]),
            "list_display": tuple(config["list_display"]),
            "allow_create": bool(config["allow_create"]),
            "allow_update": bool(config["allow_update"]),
            "allow_delete": bool(config["allow_delete"]),
        }

    async def ensure_auth_tables(
        self,
        session: AsyncSession,
        *,
        include_hidden: bool = False,
        update_titles: bool = True,
    ) -> dict[str, list[TableKey]]:
        registered = self.get_registered_admin_models(include_hidden=include_hidden)
        existing_rows = list((await session.execute(select(AuthTable))).scalars().all())
        existing_by_key = {row.key: row for row in existing_rows}

        created: list[TableKey] = []
        updated: list[TableKey] = []
        skipped: list[TableKey] = []

        for item in registered:
            table_key = item["table_key"]
            title = item["title"]
            hidden = bool(item["hidden"])
            row = existing_by_key.get(table_key)

            if row is None:
                session.add(
                    AuthTable(
                        key=table_key,
                        title=title,
                        is_service=hidden,
                    )
                )
                created.append(table_key)
                continue

            changed = False
            if update_titles and row.title != title:
                row.title = title
                changed = True
            if row.is_service != hidden:
                row.is_service = hidden
                changed = True

            if changed:
                updated.append(table_key)
            else:
                skipped.append(table_key)

        if created or updated:
            await session.commit()
        else:
            await session.flush()

        return {
            "created": created,
            "updated": updated,
            "skipped": skipped,
        }

    async def sync_auth_tables(
        self,
        session: AsyncSession,
        *,
        include_hidden: bool = False,
        update_titles: bool = True,
    ) -> dict[str, list[TableKey]]:
        return await self.ensure_auth_tables(
            session,
            include_hidden=include_hidden,
            update_titles=update_titles,
        )

    def get_access_manager(self, session: AsyncSession) -> AccessManager:
        return AccessManager(
            session,
            user_model=self._user_model,
            hidden_table_keys=self._hidden_admin_table_keys,
        )

    def _resolve_backend(
        self,
        backend: BackendName | AuthenticationBackend[_UserT, UserId] | None = None,
    ) -> AuthenticationBackend[_UserT, UserId]:
        if backend is None:
            if len(self._auth_backends) == 1:
                return self._auth_backends[0]
            available = ", ".join(self._auth_backends_by_name.keys())
            raise ConfigurationError(
                "Multiple authentication backends are configured. "
                f"Specify one explicitly. Available backends: {available}."
            )

        if isinstance(backend, str):
            try:
                return self._auth_backends_by_name[backend]
            except KeyError as exc:
                available = ", ".join(self._auth_backends_by_name.keys())
                raise ConfigurationError(
                    f"Unknown authentication backend name: {backend!r}. "
                    f"Available backends: {available}."
                ) from exc

        if backend not in self._auth_backends:
            raise ConfigurationError(
                "The provided authentication backend is not registered in FastAPIReBAC."
            )

        return backend

    def current_user(
        self,
        *,
        optional: bool = False,
        active: bool = True,
        verified: bool = False,
        superuser: bool = False,
        staff: bool = False,
        get_enabled_backends: EnabledBackendsDependency | None = None,
    ) -> CurrentUserDependency:
        cache_key = (
            optional,
            active,
            verified,
            superuser,
            staff,
            id(get_enabled_backends) if get_enabled_backends is not None else None,
        )

        cached = self._current_user_cache.get(cache_key)
        if cached is not None:
            return cached

        base_dependency = self._fastapi_users.current_user(
            optional=optional,
            active=active,
            verified=verified,
            superuser=superuser,
            get_enabled_backends=get_enabled_backends,
        )

        async def store_user_context(
            user: _UserT | None = Depends(base_dependency),
        ) -> _UserT | None:
            self._current_user_context.set(user)
            return user

        if not staff:
            self._current_user_cache[cache_key] = store_user_context
            return store_user_context

        async def current_staff_user(
            user: _UserT | None = Depends(store_user_context),
        ) -> _UserT | None:
            if user is None:
                return None

            if getattr(user, "is_staff", False):
                return user

            if optional:
                return None

            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User is not a staff member.",
            )

        self._current_user_cache[cache_key] = current_staff_user
        return current_staff_user

    @property
    def auth_required(self) -> CurrentUserDependency:
        return self.current_user()

    @property
    def verified_required(self) -> CurrentUserDependency:
        return self.current_user(verified=True)

    @property
    def superuser_required(self) -> CurrentUserDependency:
        return self.current_user(superuser=True)

    @property
    def staff_required(self) -> CurrentUserDependency:
        return self.current_user(staff=True)

    def get_auth_router(
        self,
        backend: BackendName | AuthenticationBackend[_UserT, UserId] | None = None,
        *,
        requires_verification: bool = False,
    ) -> APIRouter:
        resolved_backend = self._resolve_backend(backend)
        return self._fastapi_users.get_auth_router(
            resolved_backend,
            requires_verification=requires_verification,
        )

    def get_auth_routers(
        self,
        *,
        requires_verification: bool = False,
    ) -> list[APIRouter]:
        return [
            self._fastapi_users.get_auth_router(
                backend,
                requires_verification=requires_verification,
            )
            for backend in self._auth_backends
        ]

    def get_register_router(
        self,
        user_read_schema: type[schemas.BaseUser[UserId]] = schemas.UserRead,
        user_create_schema: type[schemas.BaseUserCreate] = schemas.UserCreate,
    ) -> APIRouter:
        return self._fastapi_users.get_register_router(
            user_read_schema,
            user_create_schema,
        )

    def get_reset_password_router(self) -> APIRouter:
        return self._fastapi_users.get_reset_password_router()

    def get_verify_router(
        self,
        user_read_schema: type[schemas.BaseUser[UserId]] = schemas.UserRead,
    ) -> APIRouter:
        return self._fastapi_users.get_verify_router(user_read_schema)

    def get_users_router(
        self,
        user_read_schema: type[schemas.BaseUser[UserId]] = schemas.UserRead,
        user_update_schema: type[schemas.BaseUserUpdate] = schemas.UserUpdate,
        *,
        requires_verification: bool = False,
    ) -> APIRouter:
        return self._fastapi_users.get_users_router(
            user_read_schema,
            user_update_schema,
            requires_verification=requires_verification,
        )

    def get_admin_router(self) -> APIRouter:
        return build_admin_router(self)

    @staticmethod
    def mount_admin_static(
        app: FastAPI,
        *,
        path: str = "/rebac-admin/static",
        name: str = "rebac_admin_static",
    ) -> None:
        """Mount bundled admin static files on the FastAPI application.

        Routers cannot serve package static files by themselves. The static app is
        mounted on the parent FastAPI application, while templates resolve it by
        the stable route name ``rebac_admin_static``.
        """
        for route in app.routes:
            if getattr(route, "name", None) == name:
                return

        static_dir = Path(__file__).resolve().parent / "static" / "rebac_admin"
        app.mount(path, StaticFiles(directory=str(static_dir)), name=name)

    @staticmethod
    def _normalize_admin_prefix(prefix: str) -> str:
        normalized = "/" + prefix.strip("/")
        return normalized.rstrip("/") or "/admin"

    @staticmethod
    def _install_admin_redirect_middleware(app: FastAPI, *, prefix: str) -> None:
        normalized_prefix = FastAPIReBAC._normalize_admin_prefix(prefix)
        state_key = "_fastapi_rebac_admin_redirect_prefixes"
        installed_prefixes = getattr(app.state, state_key, set())
        if normalized_prefix in installed_prefixes:
            return

        installed_prefixes = set(installed_prefixes)
        installed_prefixes.add(normalized_prefix)
        setattr(app.state, state_key, installed_prefixes)

        @app.middleware("http")
        async def rebac_admin_auth_redirect(request: Request, call_next):  # type: ignore[no-untyped-def]
            response = await call_next(request)
            path = request.url.path.rstrip("/") or "/"
            login_path = f"{normalized_prefix}/login"
            is_admin_path = path == normalized_prefix or path.startswith(f"{normalized_prefix}/")
            is_login_path = path == login_path or path.startswith(f"{login_path}/")
            if (
                is_admin_path
                and not is_login_path
                and request.method.upper() == "GET"
                and response.status_code == status.HTTP_401_UNAUTHORIZED
            ):
                return RedirectResponse(url=login_path, status_code=status.HTTP_303_SEE_OTHER)
            return response

    def mount_admin(
        self,
        app: FastAPI,
        *,
        prefix: str = "/admin",
        static_path: str = "/rebac-admin/static",
    ) -> None:
        """Mount admin static files, login form and admin router."""
        normalized_prefix = self._normalize_admin_prefix(prefix)
        self.mount_admin_static(app, path=static_path)
        self._install_admin_redirect_middleware(app, prefix=normalized_prefix)
        app.include_router(self.get_admin_router(), prefix=normalized_prefix)

    def get_context_user(self) -> _UserT | None:
        return self._current_user_context.get()

    def get_context_session(self) -> AsyncSession | None:
        return self._current_session_context.get()

    async def resolve_user(self, user: _UserT | None = None) -> _UserT:
        if user is not None:
            return user

        context_user = self.get_context_user()
        if context_user is None:
            raise ConfigurationError(
                "Could not resolve current user from context. Pass 'user' explicitly or use FastAPI dependencies."
            )
        return context_user

    async def resolve_session(self, session: AsyncSession | None = None) -> AsyncSession:
        if session is not None:
            return session

        context_session = self.get_context_session()
        if context_session is None:
            raise ConfigurationError(
                "Could not resolve current session from context. Pass 'session' explicitly or use FastAPI dependencies."
            )
        return context_session

    def require(self, action: ActionInput, table: TableRef) -> DependencyCallable:
        return self.access.require(action, table)

    async def resolve_require(
        self,
        action: ActionInput,
        table: TableRef,
        *,
        user: _UserT | None = None,
        session: AsyncSession | None = None,
    ) -> _UserT:
        return await self.access.resolve_require(
            action,
            table,
            user=user,
            session=session,
        )

    def accessible_select(self, user_ref_attr: UserRefAttribute) -> DependencyCallable:
        return self.access.accessible_select(user_ref_attr)

    async def resolve_accessible_select(
        self,
        user_ref_attr: UserRefAttribute,
        *,
        user: _UserT | None = None,
        session: AsyncSession | None = None,
    ) -> SelectStatement:
        return await self.access.resolve_accessible_select(
            user_ref_attr,
            user=user,
            session=session,
        )

    def require_object(
        self,
        action: ActionInput,
        user_ref_attr: UserRefAttribute,
        object_id: ObjectId | None = None,
        *,
        object_id_param: str = "id",
    ) -> DependencyCallable:
        return self.access.require_object(
            action,
            user_ref_attr,
            object_id,
            object_id_param=object_id_param,
        )

    async def resolve_require_object(
        self,
        action: ActionInput,
        user_ref_attr: UserRefAttribute,
        object_id: ObjectId,
        *,
        user: _UserT | None = None,
        session: AsyncSession | None = None,
    ) -> Any:
        return await self.access.resolve_require_object(
            action,
            user_ref_attr,
            object_id,
            user=user,
            session=session,
        )
