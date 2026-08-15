"""Session-bound signed double-submit CSRF tokens."""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
from typing import Final

from fastapi import Response
from fastapi.responses import PlainTextResponse
from starlette.requests import Request
from starlette.types import ASGIApp, Receive, Scope, Send

from app.auth.session import SESSION_COOKIE_NAME
from app.config import Settings

CSRF_COOKIE_NAME: Final = "__Host-leakcheck-csrf"
CSRF_HEADER_NAME: Final = "X-CSRF-Token"
_SAFE_METHODS: Final = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
_TOKEN_PATTERN: Final = re.compile(r"^[A-Za-z0-9_-]{43}$")
_SIGNED_TOKEN_PATTERN: Final = re.compile(r"^[A-Za-z0-9_-]{43}\.[A-Za-z0-9_-]{43}$")
_CSRF_TOKEN_BYTES: Final = 32


class CSRFProtector:
    """Issue and verify HMAC-signed tokens bound to one browser session when present."""

    def __init__(self, settings: Settings) -> None:
        self._key = hmac.new(
            settings.session_secret.get_secret_value().encode("utf-8"),
            b"leakcheck/csrf/v1",
            hashlib.sha256,
        ).digest()

    def issue(self, response: Response, *, session_token: str | None) -> str:
        """Set an origin-locked readable cookie and return the same signed value for tests."""

        nonce = secrets.token_urlsafe(_CSRF_TOKEN_BYTES)
        token = f"{nonce}.{self._signature(nonce, session_token=session_token)}"
        response.set_cookie(
            key=CSRF_COOKIE_NAME,
            value=token,
            path="/",
            secure=True,
            httponly=False,
            samesite="lax",
        )
        return token

    def valid(
        self,
        *,
        session_token: str | None,
        cookie_value: str | None,
        supplied_value: str | None,
    ) -> bool:
        """Require an exact cookie/header match and a signature for this session context."""

        if (
            not isinstance(cookie_value, str)
            or not isinstance(supplied_value, str)
            or _SIGNED_TOKEN_PATTERN.fullmatch(cookie_value) is None
            or _SIGNED_TOKEN_PATTERN.fullmatch(supplied_value) is None
            or not hmac.compare_digest(cookie_value, supplied_value)
        ):
            return False
        nonce, signature = cookie_value.split(".", maxsplit=1)
        expected_signature = self._signature(nonce, session_token=session_token)
        return hmac.compare_digest(signature, expected_signature)

    def _signature(self, nonce: str, *, session_token: str | None) -> str:
        context = _session_context(session_token)
        message = b"leakcheck/csrf/v1\x00" + context + b"\x00" + nonce.encode("ascii")
        return _base64url(hmac.new(self._key, message, hashlib.sha256).digest())


class CSRFMiddleware:
    """Reject every unsafe HTTP request that lacks a valid signed double-submit token."""

    def __init__(self, app: ASGIApp, *, protector: CSRFProtector) -> None:
        self.app = app
        self._protector = protector

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] in _SAFE_METHODS:
            await self.app(scope, receive, send)
            return
        request = Request(scope)
        if not self._protector.valid(
            session_token=request.cookies.get(SESSION_COOKIE_NAME),
            cookie_value=request.cookies.get(CSRF_COOKIE_NAME),
            supplied_value=request.headers.get(CSRF_HEADER_NAME),
        ):
            response = PlainTextResponse("CSRF validation failed.", status_code=403)
            response.headers["Cache-Control"] = "no-store"
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


def _session_context(session_token: str | None) -> bytes:
    if isinstance(session_token, str) and _TOKEN_PATTERN.fullmatch(session_token) is not None:
        return b"session\x00" + session_token.encode("ascii")
    return b"anonymous"


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
