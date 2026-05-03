from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class Yandex2FALoginChallenge(BaseModel):
    requires_2fa: bool = True
    provider: str = "yandex"
    redirect_url: str
    expires_in: int


class Yandex2FAStatus(BaseModel):
    enabled: bool
    provider: str = "yandex"
    yandex_login: str | None = None
    yandex_email: str | None = None


class Yandex2FALinkResult(BaseModel):
    enabled: bool = True
    provider: str = "yandex"
    yandex_login: str | None = None
    yandex_email: str | None = None


class Yandex2FADisableResult(BaseModel):
    enabled: bool = False
    provider: str = "yandex"


class YandexUserInfo(BaseModel):
    id: str | None = None
    psuid: str | None = None
    login: str | None = None
    default_email: str | None = None
    email: str | None = None

    model_config = ConfigDict(extra="allow")
