from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...types import UserId
from .config import Yandex2FAConfig
from .models import YandexPreAuthSession, YandexSecondFactor

LOGIN_PURPOSE = "login"
LINK_PURPOSE = "link"


class Yandex2FAError(Exception):
    """Base error for Yandex 2FA integration."""


class Yandex2FAConfigurationError(Yandex2FAError):
    """Raised when the optional integration is not configured correctly."""


class Yandex2FAOAuthError(Yandex2FAError):
    """Raised when Yandex OAuth returns an error."""


class Yandex2FAStateError(Yandex2FAError):
    """Raised when pre-auth state is missing, expired, or already consumed."""


class Yandex2FAVerificationError(Yandex2FAError):
    """Raised when Yandex account verification fails."""


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_aware_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _pkce_code_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _generate_code_verifier() -> str:
    return secrets.token_urlsafe(64)[:128]


class YandexOAuthClient:
    """Small async client for the Yandex OAuth endpoints used by this integration."""

    def __init__(self, config: Yandex2FAConfig) -> None:
        self.config = config

    def build_authorize_url(
        self,
        *,
        state: str,
        redirect_uri: str,
        code_verifier: str | None = None,
    ) -> str:
        params: dict[str, str] = {
            "response_type": "code",
            "client_id": self.config.client_id,
            "redirect_uri": redirect_uri,
            "state": state,
        }
        if self.config.scope:
            params["scope"] = self.config.scope
        if code_verifier is not None:
            params["code_challenge"] = _pkce_code_challenge(code_verifier)
            params["code_challenge_method"] = "S256"

        return f"{self.config.authorize_url}?{urlencode(params)}"

    async def exchange_code(
        self,
        *,
        code: str,
        redirect_uri: str,
        code_verifier: str | None = None,
    ) -> dict[str, Any]:
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover - depends on optional dependency
            raise Yandex2FAConfigurationError(
                "Yandex 2FA integration requires the optional dependency 'httpx'."
            ) from exc

        data: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "redirect_uri": redirect_uri,
        }
        if code_verifier is not None:
            data["code_verifier"] = code_verifier

        async with httpx.AsyncClient(timeout=self.config.request_timeout_seconds) as client:
            response = await client.post(self.config.token_url, data=data)

        if response.status_code >= 400:
            raise Yandex2FAOAuthError("Could not exchange Yandex authorization code.")

        payload = response.json()
        if not isinstance(payload, dict) or not payload.get("access_token"):
            raise Yandex2FAOAuthError("Yandex token response does not contain access_token.")
        return payload

    async def get_user_info(self, *, access_token: str) -> dict[str, Any]:
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover - depends on optional dependency
            raise Yandex2FAConfigurationError(
                "Yandex 2FA integration requires the optional dependency 'httpx'."
            ) from exc

        headers = {"Authorization": f"OAuth {access_token}"}
        params = {"format": "json"}
        async with httpx.AsyncClient(timeout=self.config.request_timeout_seconds) as client:
            response = await client.get(self.config.userinfo_url, headers=headers, params=params)

        if response.status_code >= 400:
            raise Yandex2FAOAuthError("Could not fetch Yandex user information.")

        payload = response.json()
        if not isinstance(payload, dict):
            raise Yandex2FAOAuthError("Yandex user info response is not a JSON object.")
        return payload


class Yandex2FAService:
    def __init__(
        self,
        session: AsyncSession,
        config: Yandex2FAConfig,
        *,
        oauth_client: YandexOAuthClient | None = None,
    ) -> None:
        self.session = session
        self.config = config
        self.oauth_client = oauth_client or YandexOAuthClient(config)

    async def get_binding(self, user_id: UserId) -> YandexSecondFactor | None:
        result = await self.session.execute(
            select(YandexSecondFactor).where(YandexSecondFactor.user_id == user_id)
        )
        return result.scalar_one_or_none()

    async def is_enabled(self, user_id: UserId) -> bool:
        binding = await self.get_binding(user_id)
        return bool(binding and binding.is_enabled)

    async def create_login_challenge(
        self,
        user_id: UserId,
        *,
        redirect_after: str | None = None,
        redirect_uri: str | None = None,
    ) -> tuple[YandexPreAuthSession, str]:
        return await self._create_challenge(
            user_id,
            purpose=LOGIN_PURPOSE,
            redirect_uri=redirect_uri or self.config.redirect_uri,
            redirect_after=redirect_after,
        )

    async def create_link_challenge(self, user_id: UserId) -> tuple[YandexPreAuthSession, str]:
        return await self._create_challenge(
            user_id,
            purpose=LINK_PURPOSE,
            redirect_uri=self.config.get_link_redirect_uri(),
            redirect_after=None,
        )


    async def get_preauth_purpose(self, *, state: str) -> str | None:
        result = await self.session.execute(
            select(YandexPreAuthSession.purpose).where(YandexPreAuthSession.state == state)
        )
        return result.scalar_one_or_none()

    async def complete_login(
        self,
        *,
        code: str,
        state: str,
        redirect_uri: str | None = None,
    ) -> tuple[UserId, YandexSecondFactor]:
        preauth = await self._get_valid_preauth(state=state, purpose=LOGIN_PURPOSE)
        token_payload = await self.oauth_client.exchange_code(
            code=code,
            redirect_uri=redirect_uri or self.config.redirect_uri,
            code_verifier=preauth.code_verifier,
        )
        userinfo = await self.oauth_client.get_user_info(access_token=str(token_payload["access_token"]))
        subject = self.extract_subject(userinfo)
        binding = await self.get_binding(preauth.user_id)

        if binding is None or not binding.is_enabled:
            await self._consume(preauth)
            raise Yandex2FAVerificationError("Yandex 2FA is not enabled for this user.")

        if binding.provider_subject != subject:
            await self._consume(preauth)
            raise Yandex2FAVerificationError("Yandex account does not match linked second factor.")

        self._update_binding_metadata(binding, userinfo)
        await self._consume(preauth)
        return preauth.user_id, binding

    async def complete_link(self, *, code: str, state: str) -> YandexSecondFactor:
        preauth = await self._get_valid_preauth(state=state, purpose=LINK_PURPOSE)
        token_payload = await self.oauth_client.exchange_code(
            code=code,
            redirect_uri=self.config.get_link_redirect_uri(),
            code_verifier=preauth.code_verifier,
        )
        userinfo = await self.oauth_client.get_user_info(access_token=str(token_payload["access_token"]))
        subject = self.extract_subject(userinfo)

        existing_subject = await self.session.execute(
            select(YandexSecondFactor).where(YandexSecondFactor.provider_subject == subject)
        )
        subject_binding = existing_subject.scalar_one_or_none()
        if subject_binding is not None and subject_binding.user_id != preauth.user_id:
            await self._consume(preauth)
            raise Yandex2FAVerificationError("This Yandex account is already linked to another user.")

        binding = await self.get_binding(preauth.user_id)
        if binding is None:
            binding = YandexSecondFactor(
                user_id=preauth.user_id,
                provider_subject=subject,
                is_enabled=True,
            )
            self.session.add(binding)
        else:
            binding.provider_subject = subject
            binding.is_enabled = True

        self._update_binding_metadata(binding, userinfo)
        await self._consume(preauth)
        return binding

    async def disable(self, user_id: UserId) -> None:
        binding = await self.get_binding(user_id)
        if binding is None:
            return
        binding.is_enabled = False
        await self.session.commit()

    def extract_subject(self, userinfo: dict[str, Any]) -> str:
        raw_subject = userinfo.get(self.config.subject_field)
        if raw_subject is None and self.config.subject_field != "id":
            raw_subject = userinfo.get("id")
        if raw_subject is None:
            raise Yandex2FAVerificationError(
                f"Yandex user info response does not contain subject field {self.config.subject_field!r}."
            )
        return str(raw_subject)

    async def _create_challenge(
        self,
        user_id: UserId,
        *,
        purpose: str,
        redirect_uri: str,
        redirect_after: str | None,
    ) -> tuple[YandexPreAuthSession, str]:
        state = secrets.token_urlsafe(32)
        code_verifier = _generate_code_verifier() if self.config.use_pkce else None
        now = utcnow()
        preauth = YandexPreAuthSession(
            user_id=user_id,
            state=state,
            purpose=purpose,
            code_verifier=code_verifier,
            redirect_after=redirect_after,
            expires_at=now + timedelta(seconds=self.config.preauth_ttl_seconds),
            created_at=now,
        )
        self.session.add(preauth)
        await self.session.commit()
        redirect_url = self.oauth_client.build_authorize_url(
            state=state,
            redirect_uri=redirect_uri,
            code_verifier=code_verifier,
        )
        return preauth, redirect_url

    async def _get_valid_preauth(self, *, state: str, purpose: str) -> YandexPreAuthSession:
        result = await self.session.execute(
            select(YandexPreAuthSession).where(
                YandexPreAuthSession.state == state,
                YandexPreAuthSession.purpose == purpose,
            )
        )
        preauth = result.scalar_one_or_none()
        if preauth is None:
            raise Yandex2FAStateError("Unknown Yandex 2FA state.")
        if preauth.consumed_at is not None:
            raise Yandex2FAStateError("Yandex 2FA state has already been consumed.")
        if _as_aware_utc(preauth.expires_at) <= utcnow():
            raise Yandex2FAStateError("Yandex 2FA state has expired.")
        return preauth

    def _update_binding_metadata(
        self,
        binding: YandexSecondFactor,
        userinfo: dict[str, Any],
    ) -> None:
        binding.yandex_login = self._optional_str(userinfo.get("login"))
        binding.yandex_email = self._optional_str(
            userinfo.get("default_email") or userinfo.get("email")
        )
        binding.yandex_psuid = self._optional_str(userinfo.get("psuid"))

    async def _consume(self, preauth: YandexPreAuthSession) -> None:
        preauth.consumed_at = utcnow()
        await self.session.commit()

    @staticmethod
    def _optional_str(value: Any) -> str | None:
        if value is None:
            return None
        return str(value)
