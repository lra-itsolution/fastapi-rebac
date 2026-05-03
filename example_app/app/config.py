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


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return int(raw)


def _env_float(name: str, default: float) -> float:
    raw = os.getenv(name)
    if raw is None or not raw.strip():
        return default
    return float(raw)


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

    suspicious_activity_enabled: bool = _env_bool("SUSPICIOUS_ACTIVITY_ENABLED", True)
    suspicious_activity_rules_enabled: bool = _env_bool("SUSPICIOUS_ACTIVITY_RULES_ENABLED", True)
    suspicious_activity_pyod_enabled: bool = _env_bool("SUSPICIOUS_ACTIVITY_PYOD_ENABLED", True)
    suspicious_activity_window_minutes: int = _env_int("SUSPICIOUS_ACTIVITY_WINDOW_MINUTES", 60)
    suspicious_activity_pyod_min_rows: int = _env_int("SUSPICIOUS_ACTIVITY_PYOD_MIN_ROWS", 5)
    suspicious_activity_min_events_for_pyod: int = _env_int("SUSPICIOUS_ACTIVITY_MIN_EVENTS_FOR_PYOD", 20)
    suspicious_activity_pyod_contamination: float = _env_float("SUSPICIOUS_ACTIVITY_PYOD_CONTAMINATION", 0.15)
    suspicious_activity_many_denied_threshold: int = _env_int("SUSPICIOUS_ACTIVITY_MANY_DENIED_THRESHOLD", 10)
    suspicious_activity_bulk_read_threshold: int = _env_int("SUSPICIOUS_ACTIVITY_BULK_READ_THRESHOLD", 100)
    suspicious_activity_many_deletes_threshold: int = _env_int("SUSPICIOUS_ACTIVITY_MANY_DELETES_THRESHOLD", 10)
    suspicious_activity_many_unique_objects_threshold: int = _env_int("SUSPICIOUS_ACTIVITY_MANY_UNIQUE_OBJECTS_THRESHOLD", 50)
    suspicious_activity_many_unique_ips_threshold: int = _env_int("SUSPICIOUS_ACTIVITY_MANY_UNIQUE_IPS_THRESHOLD", 3)
    suspicious_activity_night_start_hour: int = _env_int("SUSPICIOUS_ACTIVITY_NIGHT_START_HOUR", 22)
    suspicious_activity_night_end_hour: int = _env_int("SUSPICIOUS_ACTIVITY_NIGHT_END_HOUR", 6)

    first_superuser_email: str = os.getenv("FIRST_SUPERUSER_EMAIL", "admin@example.com")
    first_superuser_username: str = os.getenv("FIRST_SUPERUSER_USERNAME", "admin")
    first_superuser_password: str = os.getenv("FIRST_SUPERUSER_PASSWORD", "admin12345")


settings = Settings()
