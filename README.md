# fastapi-rebac

`fastapi-rebac` is an alpha-stage FastAPI extension for relationship-based and role-aware access control. It combines FastAPI dependencies, FastAPI Users authentication, SQLAlchemy 2.0 models, a bundled HTML admin panel, audit logging, optional suspicious-activity detection, and optional Yandex ID two-factor authentication.

The library is designed for applications where access cannot be described by simple roles only. It supports direct user permissions, group permissions, user hierarchies, object-level checks, and SQLAlchemy query filtering for objects visible to the current user.

> Status: alpha. The public API is usable, but database schema and integration APIs may still change before a stable `1.0` release.

## Features

- FastAPI dependency helpers for authenticated users, staff users, superusers, table-level permissions, object-level permissions, and accessible SQLAlchemy `select()` statements.
- SQLAlchemy 2.0 models for users, groups, group membership, registered protected tables, user permissions, group permissions, audit logs, and suspicious alerts.
- Integration layer around FastAPI Users for JWT bearer and cookie authentication backends.
- Relationship-aware visibility based on `created_by_id`, `supervisor_id`, and configurable group visibility flags.
- Bundled admin UI for users, groups, permissions, registered tables, audit logs, and suspicious alerts.
- Optional audit logging for security-relevant operations.
- Optional suspicious-activity detection with rule-based checks and PyOD ECOD outlier detection.
- Optional Yandex ID second-factor integration for API login and admin login flows.

## Installation

Core package:

```bash
pip install fastapi-rebac
```

PostgreSQL and Alembic support for production-style applications:

```bash
pip install "fastapi-rebac[postgres]"
```

Optional suspicious-activity detection:

```bash
pip install "fastapi-rebac[anomaly]"
```

Optional Yandex ID two-factor authentication:

```bash
pip install "fastapi-rebac[yandex]"
```

Everything optional:

```bash
pip install "fastapi-rebac[all]"
```

## Requirements

- Python 3.10+
- FastAPI
- FastAPI Users with SQLAlchemy support
- SQLAlchemy 2.0+
- Pydantic 2+
- Jinja2 and `python-multipart` for the bundled admin UI

The package is database-driver agnostic. Install a driver that matches your application database, for example `asyncpg` for PostgreSQL.

## Quick start

The example below shows the minimal integration shape. Real applications should keep configuration values in environment variables and create Alembic migrations for the ReBAC tables.

```python
from collections.abc import AsyncGenerator

from fastapi import Depends, FastAPI
from fastapi_users.db import SQLAlchemyUserDatabase
from sqlalchemy.ext.asyncio import AsyncSession

from fastapi_rebac import Action, FastAPIReBAC
from fastapi_rebac.auth import build_bearer_backend, build_get_user_manager
from fastapi_rebac.managers import ReBACUserManager
from fastapi_rebac.models import User

app = FastAPI()

async def get_async_session() -> AsyncGenerator[AsyncSession, None]:
    # yield your SQLAlchemy AsyncSession here
    ...

async def get_user_db(
    session: AsyncSession = Depends(get_async_session),
) -> AsyncGenerator[SQLAlchemyUserDatabase[User, str], None]:
    yield SQLAlchemyUserDatabase(session, User)

class UserManager(ReBACUserManager[User]):
    reset_password_token_secret = "change-me"
    verification_token_secret = "change-me"

get_user_manager = build_get_user_manager(UserManager, get_user_db)
auth_backend = build_bearer_backend(secret="change-me")

rebac = FastAPIReBAC(
    get_user_manager,
    [auth_backend],
    get_async_session=get_async_session,
)

app.include_router(rebac.get_auth_router(), prefix="/auth/jwt", tags=["auth"])
rebac.mount_admin(app, prefix="/admin")

@app.get("/protected")
async def protected_route(user: User = Depends(rebac.auth_required)):
    return {"user_id": str(user.id)}

@app.post("/notes", dependencies=[Depends(rebac.require(Action.CREATE, "note"))])
async def create_note():
    return {"status": "allowed"}
```

## Registering protected entities

`fastapi-rebac` stores protected entities in the `auth_table` table. Registered models are synchronized through the `FastAPIReBAC.sync_auth_tables()` helper.

```python
from sqlalchemy.ext.asyncio import AsyncSession

from my_app.models import Note

rebac.register_admin_model(
    Note,
    title="Notes",
    user_ref_attr=Note.created_by_id,
)

async def sync_rebac_tables(session: AsyncSession) -> None:
    await rebac.sync_auth_tables(session)
```

After synchronization, administrators can grant `CREATE`, `READ`, `UPDATE`, and `DELETE` permissions for the registered entity.

## Object-level access

For owned resources, pass a SQLAlchemy mapped user reference attribute. The access manager will build SQL that restricts data to the current user's visible user graph.

```python
from fastapi import Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from fastapi_rebac import Action
from my_app.models import Note

@app.get("/notes")
async def list_notes(
    stmt = Depends(rebac.accessible_select(Note.created_by_id)),
    session: AsyncSession = Depends(rebac.session_dependency),
):
    result = await session.execute(stmt.order_by(Note.created_at.desc()))
    return result.scalars().all()

@app.get("/notes/{note_id}")
async def get_note(
    note = Depends(rebac.require_object(Action.READ, Note.created_by_id, object_id_param="note_id")),
):
    return note
```

## Admin UI

The bundled admin UI is mounted on a FastAPI app with:

```python
rebac.mount_admin(app, prefix="/admin")
```

It includes pages for:

- users;
- groups and memberships;
- protected tables;
- user permissions;
- group permissions;
- audit logs;
- suspicious alerts.

The UI uses package templates and static assets from `fastapi_rebac/templates` and `fastapi_rebac/static`, so keep package data enabled when building distributions.

## Audit logging

Audit logging is enabled by default in `FastAPIReBAC`. Use the audit manager when application code performs security-relevant actions:

```python
audit = rebac.get_audit_manager(session)
await audit.log_success(
    actor_id=user.id,
    action=Action.UPDATE,
    table_key="note",
    object_id=str(note.id),
)
```

Audit events can be used for incident analysis and for suspicious-activity detection.

## Suspicious-activity detection

Install the optional extra:

```bash
pip install "fastapi-rebac[anomaly]"
```

Configure detection:

```python
from fastapi_rebac import FastAPIReBAC
from fastapi_rebac.anomaly import SuspiciousActivityConfig

rebac = FastAPIReBAC(
    get_user_manager,
    [auth_backend],
    get_async_session=get_async_session,
    suspicious_activity_config=SuspiciousActivityConfig(
        enabled=True,
        rules_enabled=True,
        pyod_enabled=True,
        window_minutes=60,
    ),
)
```

Run detection manually or from the admin UI:

```python
from fastapi_rebac.anomaly import run_suspicious_activity_detection

alerts = await run_suspicious_activity_detection(
    session,
    config=rebac.suspicious_activity_config,
)
```

Rule-based detection works without PyOD. PyOD is imported lazily and is required only when `pyod_enabled=True`.

## Yandex ID two-factor authentication

Install the optional extra:

```bash
pip install "fastapi-rebac[yandex]"
```

Then include the Yandex 2FA router instead of exposing a direct login route for users that must pass the second factor:

```python
from fastapi_rebac.integrations.yandex_2fa import Yandex2FAConfig, get_yandex_2fa_router

config = Yandex2FAConfig(
    client_id="...",
    client_secret="...",
    redirect_uri="http://127.0.0.1:8000/auth/yandex-2fa/callback",
    link_redirect_uri="http://127.0.0.1:8000/auth/yandex-2fa/link/callback",
)

app.include_router(
    get_yandex_2fa_router(rebac, config),
    prefix="/auth/yandex-2fa",
    tags=["auth"],
)
```

Do not expose a separate direct JWT login route for accounts that must use Yandex 2FA; otherwise the second factor can be bypassed.

## Examples

The repository contains two runnable examples:

- `example_app` — PostgreSQL example with JWT authentication, notes, admin UI, Alembic migrations, audit, and suspicious alerts.
- `example_yandex_2fa_app` — Yandex ID two-factor authentication example.

Typical local setup:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[example,anomaly,yandex]"
```

Then follow the README inside the selected example directory.

## Building and publishing

Build locally:

```bash
python -m pip install --upgrade build twine
python -m build
python -m twine check dist/*
```

Publish to TestPyPI:

```bash
python -m twine upload --repository testpypi dist/*
```

Publish to PyPI:

```bash
python -m twine upload dist/*
```

For GitHub Actions, prefer PyPI Trusted Publishing and the included `publish.yml` workflow.

## Development

```bash
python -m pip install -e ".[dev,all]"
python -m ruff check .
python -m pytest
python -m build
python -m twine check dist/*
```

## License

MIT License. See [LICENSE](LICENSE).
