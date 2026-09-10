"""SessionRuleEngine — CSRF extractor + 401 re-auth (B1).

Minimal but production-ready for form-heavy targets:
- Rule: extract via regex from body/header/json at extract_url, inject as header/cookie for matching scope.
- Re-auth: if 401/403 and reauth config present, re-run login sequence once and retry.

Rules are stored in RedVeilConfig.session_handling. Engine is stateless except for
cached tokens (per-rule, TTL 5min to avoid fetching on every request).
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, Field


class SessionExtractConfig(BaseModel):
    """Where to extract token from."""

    from_: str = Field(alias="from", default="body", description="body|header|json")
    regex: str = Field(..., description="Regex with one capturing group for token")
    header_name: str | None = Field(default=None, description="Header name if from=header")
    json_path: str | None = Field(default=None, description="JSON path if from=json (e.g. data.token)")

    class Config:
        populate_by_name = True


class SessionInjectConfig(BaseModel):
    """Where to inject token."""

    to: str = Field(default="header", description="header|cookie")
    name: str = Field(..., description="Header name or cookie name, e.g. X-CSRF-Token")


class SessionRuleConfig(BaseModel):
    """One session handling rule: extract → inject."""

    name: str = Field(default="csrf", description="Rule name for logs")
    extract_url: str = Field(..., description="URL to fetch for extraction, e.g. https://target/login")
    extract: SessionExtractConfig
    inject: SessionInjectConfig
    scope: str | None = Field(default=None, description="Regex scope for which request URLs this rule applies to (None = all)")
    ttl_seconds: int = Field(default=300, ge=10, le=3600)


class SessionReauthConfig(BaseModel):
    """Re-auth on 401/403 — re-run login sequence once."""

    enabled: bool = Field(default=False)
    login_url: str | None = Field(default=None, description="Login endpoint to re-auth")
    login_method: str = Field(default="POST")
    login_body: str | None = Field(default=None)
    login_headers: dict[str, str] = Field(default_factory=dict)
    max_retries: int = Field(default=1, ge=0, le=3)


class SessionHandlingConfig(BaseModel):
    """Root session handling config (additive, extra='ignore' compat)."""

    rules: list[SessionRuleConfig] = Field(default_factory=list)
    reauth: SessionReauthConfig = Field(default_factory=SessionReauthConfig)


# Runtime engine (not pydantic, holds cache and httpx logic)
@dataclass
class _CacheEntry:
    value: str
    expires_at: float


class SessionRuleEngine:
    """Applies SessionHandlingConfig to HttpClient requests."""

    def __init__(self, config: SessionHandlingConfig | None):
        self.config = config or SessionHandlingConfig()
        self._cache: dict[str, _CacheEntry] = {}

    def _is_expired(self, name: str) -> bool:
        e = self._cache.get(name)
        if not e:
            return True
        return time.monotonic() > e.expires_at

    def _scope_matches(self, rule: SessionRuleConfig, request_url: str) -> bool:
        if not rule.scope:
            return True
        try:
            return bool(re.search(rule.scope, request_url))
        except re.error:
            return True

    async def prepare_request(
        self,
        headers: dict[str, str],
        cookies: dict[str, str],
        request_url: str,
        request_method: str,
        http_client: Any,  # HttpClient, avoid circular import
    ) -> None:
        """Fetch and inject tokens for matching rules (called pre-send)."""
        for rule in self.config.rules:
            if not self._scope_matches(rule, request_url):
                continue
            # Use cache if fresh
            if not self._is_expired(rule.name) and self._cache[rule.name].value:
                val = self._cache[rule.name].value
            else:
                val = await self._fetch_token(rule, http_client)
                if val is None:
                    continue
                self._cache[rule.name] = _CacheEntry(value=val, expires_at=time.monotonic() + rule.ttl_seconds)
            # Inject
            if rule.inject.to == "header":
                headers[rule.inject.name] = val
            elif rule.inject.to == "cookie":
                cookies[rule.inject.name] = val

    async def _fetch_token(self, rule: SessionRuleConfig, http_client: Any) -> str | None:
        """Fetch extract_url and extract token via regex."""
        try:
            from redveil.http.request import Request

            req = Request(method="GET", url=rule.extract_url, purpose="session_rule")
            resp = await http_client.send_raw(req)  # bypass rule recursion
            # Extract
            source = ""
            if rule.extract.from_ == "body":
                source = resp.body
            elif rule.extract.from_ == "header":
                hn = (rule.extract.header_name or "").lower()
                source = ""
                for k, v in resp.headers.items():
                    if k.lower() == hn:
                        source = v
                        break
            elif rule.extract.from_ == "json":
                # Simple json path: a.b.c
                try:
                    import json

                    data = json.loads(resp.body)
                    cur: Any = data
                    if rule.extract.json_path:
                        for part in rule.extract.json_path.split("."):
                            if isinstance(cur, dict):
                                cur = cur.get(part)
                            else:
                                cur = None
                                break
                    source = str(cur) if cur is not None else ""
                except Exception:
                    source = resp.body
            else:
                source = resp.body

            m = re.search(rule.extract.regex, source, re.DOTALL)
            if m:
                # Group 1 if exists, else group 0
                try:
                    return m.group(1) if m.lastindex and m.lastindex >= 1 else m.group(0)
                except IndexError:
                    return m.group(0)
        except Exception:
            pass
        return None

    async def handle_401(
        self,
        request_url: str,
        request_method: str,
        response_status: int,
        headers: dict[str, str],
        cookies: dict[str, str],
        http_client: Any,
    ) -> bool:
        """Handle 401/403 by re-authing once. Returns True if retried."""
        if response_status not in (401, 403):
            return False
        if not self.config.reauth.enabled or not self.config.reauth.login_url:
            return False
        # Simple retry once: POST to login_url
        try:
            from redveil.http.request import Request

            body = self.config.reauth.login_body
            hdrs = dict(self.config.reauth.login_headers)
            req = Request(
                method=self.config.reauth.login_method.upper(),
                url=self.config.reauth.login_url,
                headers=hdrs,
                body=body,
                purpose="session_reauth",
            )
            resp = await http_client.send_raw(req)
            # Update cookies from Set-Cookie if any
            set_cookie = resp.headers.get("set-cookie") or resp.headers.get("Set-Cookie")
            if set_cookie:
                # Simple parse: a=b; Path=/
                for part in set_cookie.split(","):
                    if "=" in part:
                        kv = part.split(";")[0].strip()
                        if "=" in kv:
                            k, v = kv.split("=", 1)
                            cookies[k.strip()] = v.strip()
            # Invalidate cache so next prepare will refetch CSRF
            self._cache.clear()
            return True
        except Exception:
            return False
