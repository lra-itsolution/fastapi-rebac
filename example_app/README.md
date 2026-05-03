# fastapi-rebac example app

This is a minimal FastAPI application that shows how to use `fastapi-rebac` with PostgreSQL.

The example includes:

- JWT authentication through the public `fastapi_rebac` API;
- the default `fastapi_rebac.models.User` database model;
- one custom application model: `Note`;
- table-level and object-level ReBAC checks for `Note` records through `Note.created_by_id`;
- the built-in `fastapi-rebac` admin UI at `/admin`;
- Alembic migrations for PostgreSQL;
- optional suspicious activity detection with rule-based checks and PyOD ECOD.

The application code does not import from `fastapi_users` directly. Authentication internals are encapsulated by `fastapi-rebac`.

## Project structure

```text
example_app/
  .env.example
  README.md
  alembic.ini
  alembic/
    env.py
    versions/
      20260502_0001_initial.py
      20260503_0002_suspicious_alert.py
  app/
    auth.py
    config.py
    db.py
    main.py
    models.py
    schemas.py
    seed_admin.py
```

## 1. Start PostgreSQL

### Linux / macOS

```bash
docker run --name rebac-postgres \
  -e POSTGRES_USER=rebac \
  -e POSTGRES_PASSWORD=rebac \
  -e POSTGRES_DB=rebac_example \
  -p 5432:5432 \
  -d postgres:16
```

### Windows PowerShell

```powershell
docker run --name rebac-postgres `
  -e POSTGRES_USER=rebac `
  -e POSTGRES_PASSWORD=rebac `
  -e POSTGRES_DB=rebac_example `
  -p 5432:5432 `
  -d postgres:16
```

Default database URL:

```text
postgresql+asyncpg://rebac:rebac@localhost:5432/rebac_example
```

If the container already exists, start it instead:

### Linux / macOS

```bash
docker start rebac-postgres
```

### Windows PowerShell

```powershell
docker start rebac-postgres
```

## 2. Create a virtual environment and install dependencies

Run the commands from the project root.

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[example,anomaly]"
```

### Windows PowerShell

```powershell
py -3.10 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[example,anomaly]"
```

If PowerShell blocks script execution, run:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Then activate the environment again.

## 3. Configure environment variables

Copy the example environment file.

### Linux / macOS

```bash
cp example_app/.env.example .env
```

### Windows PowerShell

```powershell
Copy-Item example_app\.env.example .env
```

Default `.env` values:

```env
DATABASE_URL=postgresql+asyncpg://rebac:rebac@localhost:5432/rebac_example
JWT_SECRET=change-me-jwt-secret
RESET_PASSWORD_SECRET=change-me-reset-secret
VERIFICATION_SECRET=change-me-verify-secret
CSRF_SECRET=change-me-csrf-secret
COOKIE_SECURE=false
SQL_ECHO=false
FIRST_SUPERUSER_EMAIL=admin@example.com
FIRST_SUPERUSER_USERNAME=admin
FIRST_SUPERUSER_PASSWORD=admin12345
SUSPICIOUS_ACTIVITY_ENABLED=true
SUSPICIOUS_ACTIVITY_RULES_ENABLED=true
SUSPICIOUS_ACTIVITY_PYOD_ENABLED=true
SUSPICIOUS_ACTIVITY_WINDOW_MINUTES=60
```

`COOKIE_SECURE=false` is intended only for local HTTP development. In production, use HTTPS and set it to `true`.

## 4. Run migrations

The example uses Alembic. The migrations create the `fastapi-rebac` tables, the optional `suspicious_alert` table, and the custom `note` table.

### Linux / macOS

```bash
alembic -c example_app/alembic.ini upgrade head
```

### Windows PowerShell

```powershell
alembic -c example_app\alembic.ini upgrade head
```

The migrations create:

- `user`;
- `auth_table`;
- `group`;
- `group_membership`;
- `user_permission`;
- `group_permission`;
- `audit_log`;
- `suspicious_alert`;
- `note`.

### Creating new migrations

After changing models, generate a migration and review it before applying.

#### Linux / macOS

```bash
alembic -c example_app/alembic.ini revision --autogenerate -m "change models"
alembic -c example_app/alembic.ini upgrade head
```

#### Windows PowerShell

```powershell
alembic -c example_app\alembic.ini revision --autogenerate -m "change models"
alembic -c example_app\alembic.ini upgrade head
```

Always inspect the generated file in `example_app/alembic/versions/` before running `upgrade head`.

## 5. Create the first administrator

After applying migrations, create the first `superuser` / `staff` account.

### Linux / macOS

```bash
python -m example_app.app.seed_admin
```

### Windows PowerShell

```powershell
python -m example_app.app.seed_admin
```

Default credentials:

```text
email: admin@example.com
password: admin12345
username: admin
```

You can change these values in `.env`.

## 6. Run the application

### Linux / macOS

```bash
uvicorn example_app.app.main:app --reload
```

### Windows PowerShell

```powershell
uvicorn example_app.app.main:app --reload
```

Open:

```text
http://127.0.0.1:8000/docs
http://127.0.0.1:8000/admin
http://127.0.0.1:8000/health
```

## 7. Authentication

Login endpoint:

```text
POST /auth/jwt/login
```

It accepts form data. The `username` field is the user's email.

### Linux / macOS

```bash
curl -X POST http://127.0.0.1:8000/auth/jwt/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin@example.com&password=admin12345"
```

### Windows PowerShell

```powershell
$response = Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:8000/auth/jwt/login" `
  -ContentType "application/x-www-form-urlencoded" `
  -Body "username=admin@example.com&password=admin12345"

$response.access_token
```

Use the returned token for authenticated requests.

### Linux / macOS

```bash
TOKEN="paste-access-token-here"

curl http://127.0.0.1:8000/users/me \
  -H "Authorization: Bearer $TOKEN"
```

### Windows PowerShell

```powershell
$token = "paste-access-token-here"

Invoke-RestMethod `
  -Method Get `
  -Uri "http://127.0.0.1:8000/users/me" `
  -Headers @{ Authorization = "Bearer $token" }
```

## 8. The custom `Note` model

The example has one custom application model:

```text
example_app/app/models.py
```

```python
class Note(UUIDPKMixin, TimestampMixin, Base):
    __tablename__ = "note"

    title: Mapped[str]
    body: Mapped[str | None]
    created_by_id: Mapped[UUID]
```

It is registered in `main.py`:

```python
rebac.register_admin_model(
    Note,
    title="Notes",
    user_ref_attr=Note.created_by_id,
    list_display=("id", "title", "created_by_id", "created_at"),
    readonly_fields={"created_at", "updated_at"},
)
```

`user_ref_attr=Note.created_by_id` tells `fastapi-rebac` that object visibility is based on the owner of the row.

## 9. Protected endpoints

Create requires table-level `CREATE` access to `note`:

```python
user: User = Depends(rebac.require(Action.CREATE, Note.created_by_id))
```

List uses object-level filtering:

```python
stmt: Any = Depends(rebac.accessible_select(Note.created_by_id))
```

Read/update/delete use object-level checks:

```python
Depends(rebac.require_object(Action.READ, Note.created_by_id, object_id_param="note_id"))
Depends(rebac.require_object(Action.UPDATE, Note.created_by_id, object_id_param="note_id"))
Depends(rebac.require_object(Action.DELETE, Note.created_by_id, object_id_param="note_id"))
```

## 10. Granting access to a regular user

A superuser can access all registered tables. For regular users, grant permissions through the admin UI:

1. Open `/admin` as the superuser.
2. Open `Users`.
3. Select a user.
4. Add permissions for the `note` table:
   - `CREATE`;
   - `READ`;
   - `UPDATE`;
   - `DELETE`.

You can also grant permissions through groups.

## 11. Create and read notes

### Linux / macOS

```bash
TOKEN="paste-access-token-here"

curl -X POST http://127.0.0.1:8000/notes \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"title":"First note","body":"Hello from fastapi-rebac"}'

curl http://127.0.0.1:8000/notes \
  -H "Authorization: Bearer $TOKEN"
```

### Windows PowerShell

```powershell
$token = "paste-access-token-here"

Invoke-RestMethod `
  -Method Post `
  -Uri "http://127.0.0.1:8000/notes" `
  -Headers @{ Authorization = "Bearer $token" } `
  -ContentType "application/json" `
  -Body '{"title":"First note","body":"Hello from fastapi-rebac"}'

Invoke-RestMethod `
  -Method Get `
  -Uri "http://127.0.0.1:8000/notes" `
  -Headers @{ Authorization = "Bearer $token" }
```


## Suspicious activity detection

The example enables the optional MVP detector in `example_app/app/main.py`:

```python
suspicious_activity_config=SuspiciousActivityConfig(
    enabled=settings.suspicious_activity_enabled,
    rules_enabled=settings.suspicious_activity_rules_enabled,
    pyod_enabled=settings.suspicious_activity_pyod_enabled,
    window_minutes=settings.suspicious_activity_window_minutes,
)
```

How it works:

```text
audit_log → activity-window features → rule checks + PyOD ECOD → suspicious_alert
```

PyOD is used inside the library in `fastapi_rebac/anomaly/pyod_detector.py`.
It is called by `run_suspicious_activity_detection()` when `pyod_enabled=True`, PyOD is installed, and there are enough activity rows for analysis.

To run detection manually, open the admin panel and go to:

```text
Administration → Suspicious alerts → Run detection
```

The button runs the configured detectors and saves new rows to `suspicious_alert`.
The detector does not block users and does not change `audit_log`.

## 12. Common issues

### `relation "user" does not exist`

Run migrations first:

```bash
alembic -c example_app/alembic.ini upgrade head
```

On Windows PowerShell:

```powershell
alembic -c example_app\alembic.ini upgrade head
```

### The admin UI opens, but CSS is missing

Use:

```python
rebac.mount_admin(app, prefix="/admin")
```

This method includes both the admin router and static files.

### Admin login works, but permissions are missing

Run the seed command after migrations. It synchronizes registered authorization tables and creates the first admin user:

```bash
python -m example_app.app.seed_admin
```

On Windows PowerShell:

```powershell
python -m example_app.app.seed_admin
```


## Admin web login

The example configures two authentication backends:

- `jwt` for Swagger/API requests;
- `cookie` for the browser-based admin panel.

Open the admin login form at:

```text
http://127.0.0.1:8000/admin/login
```

Use the seeded administrator credentials:

```text
Email: admin@example.com
Password: admin12345
```

For local HTTP development keep this value in `.env`:

```env
COOKIE_SECURE=false
```
