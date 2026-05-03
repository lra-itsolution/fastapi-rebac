from __future__ import annotations

import os
from dataclasses import dataclass

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - dotenv is only needed for local example runs
    load_dotenv = None

if load_dotenv is not None:
    load_dotenv()


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    database_url: str = os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://rebac:rebac@localhost:5432/rebac_example",
    )
    jwt_secret: str = os.getenv("JWT_SECRET", "change-me-jwt-secret")
    reset_password_secret: str = os.getenv("RESET_PASSWORD_SECRET", "change-me-reset-secret")
    verification_secret: str = os.getenv("VERIFICATION_SECRET", "change-me-verify-secret")
    csrf_secret: str = os.getenv("CSRF_SECRET", "change-me-csrf-secret")
    cookie_secure: bool = _env_bool("COOKIE_SECURE", False)
    sql_echo: bool = _env_bool("SQL_ECHO", False)

    first_superuser_email: str = os.getenv("FIRST_SUPERUSER_EMAIL", "admin@example.com")
    first_superuser_username: str = os.getenv("FIRST_SUPERUSER_USERNAME", "admin")
    first_superuser_password: str = os.getenv("FIRST_SUPERUSER_PASSWORD", "admin12345")

    yandex_client_id: str = os.getenv("YANDEX_CLIENT_ID", "change-me-yandex-client-id")
    yandex_client_secret: str = os.getenv("YANDEX_CLIENT_SECRET", "change-me-yandex-client-secret")
    yandex_redirect_uri: str = os.getenv(
        "YANDEX_REDIRECT_URI",
        "http://127.0.0.1:8000/auth/yandex-2fa/callback",
    )
    yandex_link_redirect_uri: str = os.getenv(
        "YANDEX_LINK_REDIRECT_URI",
        "http://127.0.0.1:8000/auth/yandex-2fa/link/callback",
    )
    yandex_admin_redirect_uri: str = os.getenv(
        "YANDEX_ADMIN_REDIRECT_URI",
        "http://127.0.0.1:8000/admin/yandex-2fa/callback",
    )


settings = Settings()
