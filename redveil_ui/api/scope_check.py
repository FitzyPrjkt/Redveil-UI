"""Synchronous scope validation for target creation and scan launch.

The HttpClient/ScopeController pair still enforces scope at request time
(defense in depth). This module is the FIRST line — it lets the API
return a synchronous 4xx instead of starting an orchestrator that will
fail mid-run when the first request is out of scope.

The check mirrors scanner.py:_build_config's YAML parsing rules:
- ``scope_yaml`` may be a top-level scope dict, or a full RedVeilConfig
  with a nested ``scope`` block.
- Empty/missing ``allowed_hosts`` falls back to auto-allowing the
  target host (matches scanner behavior at scanner.py:84).
- Path matching is fnmatch-style (so ``/*`` matches everything, and
  ``/api/*`` matches ``/api/v1`` but not ``/admin``).
"""
from __future__ import annotations

import fnmatch
from urllib.parse import urlparse

import yaml


def check_target_url_in_scope(url: str, scope_yaml: str | None) -> tuple[bool, str]:
    """Return ``(ok, reason)``.

    ``ok=True`` means the URL passes scope under the given ``scope_yaml``.
    ``reason`` is empty on success; on failure it is a human-readable
    explanation suitable for an HTTP 422 detail string.
    """
    if not url:
        return False, "empty url"

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or "/"

    if not scope_yaml:
        # No scope_yaml — equivalent to scanner's auto-allow behavior.
        return True, ""

    try:
        parsed_yaml = yaml.safe_load(scope_yaml) or {}
    except yaml.YAMLError as exc:
        return False, f"invalid scope_yaml: {exc}"

    if not isinstance(parsed_yaml, dict):
        return True, ""

    scope = parsed_yaml
    if "scope" in parsed_yaml and isinstance(parsed_yaml["scope"], dict):
        scope = parsed_yaml["scope"]

    allowed_hosts = [h.lower() for h in (scope.get("allowed_hosts") or [])]
    allowed_paths = scope.get("allowed_paths") or ["/*"]
    excluded_paths = scope.get("excluded_paths") or []

    # If no allowed_hosts set, treat as auto-allow (matches scanner.py:84).
    if not allowed_hosts:
        return True, ""

    if host not in allowed_hosts:
        return False, f"host '{host}' is not in scope.allowed_hosts"

    if not _match_path(path, allowed_paths):
        return False, f"path '{path}' matches no allowed_paths entry"

    if _match_path(path, excluded_paths):
        return False, f"path '{path}' matches an excluded_paths entry"

    return True, ""


def _match_path(path: str, patterns: list[str]) -> bool:
    """fnmatch-style glob match against a list of patterns."""
    return any(fnmatch.fnmatch(path, pattern) for pattern in patterns)


__all__ = ["check_target_url_in_scope"]
