from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Yandex2FAConfig:
    """Configuration for using Yandex ID as a second authentication factor."""

    client_id: str
    client_secret: str
    redirect_uri: str
    link_redirect_uri: str | None = None

    scope: str | None = "login:info login:email"
    authorize_url: str = "https://oauth.yandex.ru/authorize"
    token_url: str = "https://oauth.yandex.ru/token"
    userinfo_url: str = "https://login.yandex.ru/info"

    preauth_ttl_seconds: int = 600
    use_pkce: bool = True
    subject_field: str = "id"
    request_timeout_seconds: float = 10.0

    def get_link_redirect_uri(self) -> str:
        return self.link_redirect_uri or self.redirect_uri
