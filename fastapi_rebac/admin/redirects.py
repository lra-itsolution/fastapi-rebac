from __future__ import annotations

from typing import Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fastapi import Request


def normalize_prefix(prefix: str) -> str:
    normalized = "/" + prefix.strip("/")
    return normalized.rstrip("/") or "/"


def request_path_with_query(request: Request) -> str:
    path = request.url.path or "/"
    if request.url.query:
        return f"{path}?{request.url.query}"
    return path


def is_safe_relative_url(value: str | None) -> bool:
    if not value:
        return False
    parts = urlsplit(value)
    if parts.scheme or parts.netloc:
        return False
    if not parts.path.startswith("/"):
        return False
    if parts.path.startswith("//"):
        return False
    return True


def safe_relative_url(value: str | None, *, default: str | None = None) -> str | None:
    if is_safe_relative_url(value):
        return value
    return default


def path_matches_prefix(path: str, prefix: str) -> bool:
    normalized_prefix = normalize_prefix(prefix)
    normalized_path = path.rstrip("/") or "/"
    if normalized_prefix == "/":
        return True
    return normalized_path == normalized_prefix or normalized_path.startswith(f"{normalized_prefix}/")


def any_path_matches_prefix(path: str, prefixes: Iterable[str]) -> bool:
    return any(path_matches_prefix(path, prefix) for prefix in prefixes)


def append_next_param(login_url: str, next_url: str | None) -> str:
    if not next_url:
        return login_url

    parts = urlsplit(login_url)
    query = parse_qsl(parts.query, keep_blank_values=True)
    query = [(key, value) for key, value in query if key != "next"]
    query.append(("next", next_url))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def path_from_url(url: str) -> str | None:
    parts = urlsplit(url)
    if parts.scheme or parts.netloc:
        return None
    if not parts.path:
        return "/"
    return parts.path.rstrip("/") or "/"
