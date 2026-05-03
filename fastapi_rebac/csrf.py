import hashlib
import hmac
import secrets
from fastapi import HTTPException, Request, Response, status

from .types import CookieSameSite


class CSRFManager:
    def __init__(
        self,
        *,
        secret_key: str,
        cookie_name: str = "rebac_csrf_token",
        form_field_name: str = "csrf_token",
        cookie_secure: bool = True,
        cookie_samesite: CookieSameSite = "lax",
        cookie_path: str = "/",
    ) -> None:
        self.secret_key = secret_key.encode()
        self.cookie_name = cookie_name
        self.form_field_name = form_field_name
        self.cookie_secure = cookie_secure
        self.cookie_samesite = cookie_samesite
        self.cookie_path = cookie_path

    def _sign(self, token: str) -> str:
        return hmac.new(self.secret_key, token.encode(), hashlib.sha256).hexdigest()

    def _serialize(self, token: str) -> str:
        return f"{token}.{self._sign(token)}"

    def _deserialize(self, value: str | None) -> str | None:
        if not value or "." not in value:
            return None

        token, signature = value.rsplit(".", 1)
        expected = self._sign(token)
        if not hmac.compare_digest(signature, expected):
            return None
        return token

    def extract_token(self, request: Request) -> str | None:
        return self._deserialize(request.cookies.get(self.cookie_name))

    def needs_cookie_refresh(self, request: Request) -> bool:
        return self.extract_token(request) is None

    def get_or_create_token(self, request: Request) -> str:
        token = self.extract_token(request)
        return token or secrets.token_urlsafe(32)

    def set_cookie(self, response: Response, token: str) -> None:
        response.set_cookie(
            key=self.cookie_name,
            value=self._serialize(token),
            httponly=True,
            secure=self.cookie_secure,
            samesite=self.cookie_samesite,
            path=self.cookie_path,
        )

    async def validate_request(self, request: Request) -> None:
        cookie_token = self.extract_token(request)
        if cookie_token is None:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid CSRF token.",
            )

        form = await request.form()
        form_token = form.get(self.form_field_name)
        if not isinstance(form_token, str):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid CSRF token.",
            )

        if not hmac.compare_digest(cookie_token, form_token):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid CSRF token.",
            )

    async def protect(self, request: Request) -> None:
        await self.validate_request(request)
