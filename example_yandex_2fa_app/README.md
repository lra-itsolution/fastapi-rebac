# fastapi-rebac Yandex 2FA example

This example shows how to use `fastapi-rebac` with optional Yandex ID two-factor authentication.

The example uses:

- FastAPI
- PostgreSQL
- SQLAlchemy async sessions
- Alembic migrations
- `fastapi-rebac` core models
- `fastapi_rebac.integrations.yandex_2fa`
- JWT for API clients
- Cookie authentication for the HTML admin panel

## Important security note

`/auth/yandex-2fa/login` is the login endpoint used by this example.

If a user has no linked Yandex second factor yet, the endpoint returns the final JWT after a successful password check. After the user links Yandex ID, the same endpoint requires Yandex confirmation before it returns the final JWT.

Do not expose a separate direct JWT login route for users that must pass 2FA, otherwise they can bypass the second factor.

The HTML admin panel uses `/admin/login`. If Yandex 2FA is enabled for a staff user, admin login redirects to Yandex and only sets the admin cookie after the callback succeeds.

## PostgreSQL

Create a database and user, for example:

```sql
CREATE USER rebac WITH PASSWORD 'rebac';
CREATE DATABASE rebac_yandex_example OWNER rebac;
GRANT ALL PRIVILEGES ON DATABASE rebac_yandex_example TO rebac;
```

## Environment variables

Copy `.env.example` to `.env` and update it.

Linux / macOS:

```bash
cp example_yandex_2fa_app/.env.example .env
```

Windows PowerShell:

```powershell
Copy-Item example_yandex_2fa_app\.env.example .env
```

Example values:

```env
DATABASE_URL=postgresql+asyncpg://rebac:rebac@127.0.0.1:5432/rebac_yandex_example
JWT_SECRET=change-me-jwt-secret
RESET_PASSWORD_SECRET=change-me-reset-secret
VERIFICATION_SECRET=change-me-verify-secret
CSRF_SECRET=change-me-csrf-secret
COOKIE_SECURE=false

YANDEX_CLIENT_ID=your-yandex-client-id
YANDEX_CLIENT_SECRET=your-yandex-client-secret
YANDEX_REDIRECT_URI=http://127.0.0.1:8000/auth/yandex-2fa/callback
YANDEX_LINK_REDIRECT_URI=http://127.0.0.1:8000/auth/yandex-2fa/link/callback
YANDEX_ADMIN_REDIRECT_URI=http://127.0.0.1:8000/admin/yandex-2fa/callback
```

In Yandex OAuth settings, register all redirect URIs listed above.

## Install dependencies

Linux / macOS:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[example,yandex]"
```

Windows PowerShell:

```powershell
py -3.10 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[example,yandex]"
```

## Run migrations

Linux / macOS:

```bash
alembic -c example_yandex_2fa_app/alembic.ini upgrade head
```

Windows PowerShell:

```powershell
alembic -c example_yandex_2fa_app\alembic.ini upgrade head
```

The example app includes application-level migrations for:

- core `fastapi-rebac` tables;
- optional Yandex 2FA tables;
- `suspicious_alert` anomaly table.

The library itself does not apply optional Yandex migrations automatically.

## Create admin user

Linux / macOS:

```bash
python -m example_yandex_2fa_app.app.seed_admin
```

Windows PowerShell:

```powershell
python -m example_yandex_2fa_app.app.seed_admin
```

Default credentials:

- email: `admin@example.com`
- password: `admin12345`

## Run the app

Linux / macOS:

```bash
uvicorn example_yandex_2fa_app.app.main:app --reload
```

Windows PowerShell:

```powershell
uvicorn example_yandex_2fa_app.app.main:app --reload
```

Open:

- http://127.0.0.1:8000/docs
- http://127.0.0.1:8000/admin/

## API flow

1. Call `POST /auth/yandex-2fa/login` with `username` and `password`.
2. If Yandex 2FA is not linked, the endpoint returns a JWT.
3. Authorize in Swagger with that JWT.
4. Call `POST /auth/yandex-2fa/link` to get a Yandex link URL.
5. Open the `redirect_url`, confirm Yandex, and complete linking.
6. Call `POST /auth/yandex-2fa/login` again.
7. The endpoint now returns `requires_2fa=true` and `redirect_url`.
8. Open `redirect_url`, confirm Yandex, and the callback completes login.

## Admin flow

1. Open `http://127.0.0.1:8000/admin/`.
2. Log in with email and password.
3. If Yandex 2FA is enabled for that staff user, the admin login redirects to Yandex.
4. After the Yandex callback succeeds, the admin cookie is set and the browser is redirected to `/admin/`.

The admin Yandex 2FA callback is provided by the integration module, not by `FastAPIReBAC` itself:

```python
from fastapi_rebac.integrations.yandex_2fa import get_yandex_2fa_admin_router

app.include_router(
    get_yandex_2fa_admin_router(
        rebac,
        yandex_2fa_config,
        backend="cookie",
        redirect_uri=settings.yandex_admin_redirect_uri,
    ),
    prefix="/admin",
)
```

## Migrations in real applications

The library does not ship mandatory Yandex migrations inside `fastapi_rebac`. For a real application, import the optional models in your Alembic `env.py`:

```python
import fastapi_rebac.integrations.yandex_2fa.models  # noqa: F401
```

Then generate the migration inside your application:

Linux / macOS:

```bash
alembic revision --autogenerate -m "add yandex 2fa"
alembic upgrade head
```

Windows PowerShell:

```powershell
alembic revision --autogenerate -m "add yandex 2fa"
alembic upgrade head
```

This example app already includes application-level migrations, so you only need to run `upgrade head` for the example.
