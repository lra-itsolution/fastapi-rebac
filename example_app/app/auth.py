from __future__ import annotations

from fastapi_rebac.auth import (
    ReBACUserManager,
    build_bearer_backend,
    build_cookie_backend,
    build_get_user_manager,
)
from fastapi_rebac.db.adapters import build_get_user_db
from fastapi_rebac.models import User

from .config import settings
from .db import get_async_session


class UserManager(ReBACUserManager[User]):
    reset_password_token_secret = settings.reset_password_secret
    verification_token_secret = settings.verification_secret


get_user_db = build_get_user_db(User, get_async_session)
get_user_manager = build_get_user_manager(UserManager, get_user_db)

auth_backend = build_bearer_backend(
    secret=settings.jwt_secret,
    token_url="auth/jwt/login",
    name="jwt",
    lifetime_seconds=3600,
)


cookie_auth_backend = build_cookie_backend(
    secret=settings.jwt_secret,
    name="cookie",
    cookie_secure=settings.cookie_secure,
    lifetime_seconds=3600,
)
