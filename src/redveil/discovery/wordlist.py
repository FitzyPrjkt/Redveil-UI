"""WordlistManager — central discovery wordlist for A2.

Consolidates the 17 _DEBUG_PATHS + 9 _COMMON_MAP_PATHS + 11 seed paths that were
previously hard-coded across three modules. Provides:

* `WordlistManager.builtin()` — the curated default wordlist (debug, backup, map, seeds, extensions)
* `WordlistManager.from_file(path)` — load SecLists/external wordlist (one entry per line, skip #)
* `generate_candidates(base, wordlist=None)` — join base + wordlist entries
* `is_soft_404(resp, baseline_404_body)` — compare body hash/length/status to detect soft-404
* `extensions_for(path)` — generate .bak/.old/.zip etc variants (capability, not auto-run)

Used by InfoDisclosureCheck, SourceMapCheck, and AttackSurfaceMapper. Not auto-run by
the crawler yet — Phase B will wire it into the crawl frontier.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Iterable

from redveil.util.urls import join_url

# Migrated hard-coded lists (previously scattered)
_BUILTIN_DEBUG_PATHS = [
    "/.env",
    "/debug",
    "/server-status",
    "/server-info",
    "/phpinfo.php",
    "/info.php",
    "/api/debug",
    "/api/_debug",
    "/admin/debug",
    "/.git/HEAD",
    "/.svn/entries",
    "/config.json",
    "/config.yaml",
    "/swagger.json",
    "/api-docs",
    "/openapi.json",
    "/.well-known/",
    "/api/source-map",
]

_BUILTIN_BACKUP_PATHS = [
    "/index.php~",
    "/index.php.bak",
    "/.DS_Store",
    "/wp-config.php.bak",
    "/.htaccess.bak",
    "/.env.bak",
    "/app.py.bak",
    "/server.py.bak",
]

_BUILTIN_MAP_PATHS = [
    "/static/js/main.js.map",
    "/app.js.map",
    "/bundle.js.map",
    "/assets/index.js.map",
    "/js/main.js.map",
    "/dist/bundle.js.map",
    "/build/app.js.map",
    "/main.js.map",
    "/index.js.map",
]

_BUILTIN_SEED_PATHS = [
    "/api/profile/me",
    "/api/user/me",
    "/api/users/me",
    "/api/me",
    "/api/orders",
    "/api/orders/1",
    "/api/admin/users",
    "/api/v1/profile",
    "/api/v1/user",
    "/api/v1/users/me",
    "/api/v1/admin/users",
    "/graphql",
]

# Extensions for backup discovery (A2 capability, not auto-run)
_BACKUP_EXTENSIONS = [".bak", ".old", ".backup", ".zip", ".tar.gz", ".orig", ".swp", "~"]

# Common wordlist for content discovery (short, high-signal, not SecLists full)
_COMMON_DISCOVERY_WORDS = [
    "admin", "api", "backup", "config", "debug", "login", "test", "dev",
    "staging", "internal", "private", "secret", "data", "old", "new",
    "v1", "v2", "v3", "beta", "demo", "tmp", "temp", "backup", "db",
]


class WordlistManager:
    """Central wordlist for discovery probes."""

    def __init__(self, words: list[str] | None = None):
        self.words: list[str] = words or []

    @classmethod
    def builtin(cls) -> "WordlistManager":
        """Curated default wordlist (debug + backup + map + seeds + common)."""
        words: list[str] = []
        words.extend(_BUILTIN_DEBUG_PATHS)
        words.extend(_BUILTIN_BACKUP_PATHS)
        words.extend(_BUILTIN_MAP_PATHS)
        words.extend(_BUILTIN_SEED_PATHS)
        # Add common discovery words as /word
        for w in _COMMON_DISCOVERY_WORDS:
            words.append(f"/{w}")
            words.append(f"/api/{w}")
        # Deduplicate preserving order
        seen: set[str] = set()
        deduped: list[str] = []
        for w in words:
            if w not in seen:
                seen.add(w)
                deduped.append(w)
        return cls(deduped)

    @classmethod
    def from_file(cls, path: str | Path, max_entries: int = 10000) -> "WordlistManager":
        """Load wordlist from file (one entry per line, skip # and empty, cap 10k)."""
        p = Path(path).expanduser()
        if not p.exists():
            raise FileNotFoundError(f"wordlist not found: {p}")
        words: list[str] = []
        for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            # Normalize to /path
            if not s.startswith("/"):
                s = "/" + s
            words.append(s)
            if len(words) >= max_entries:
                break
        return cls(words)

    def with_extensions(self, extensions: Iterable[str] | None = None) -> list[str]:
        """Generate extension variants for each word (e.g. /config → /config.bak)."""
        exts = list(extensions or _BACKUP_EXTENSIONS)
        out: list[str] = []
        for w in self.words:
            out.append(w)
            for ext in exts:
                # Don't double-extend already-extensioned paths
                if w.endswith(ext):
                    continue
                out.append(w + ext)
        # Dedup
        seen: set[str] = set()
        deduped: list[str] = []
        for w in out:
            if w not in seen:
                seen.add(w)
                deduped.append(w)
        return deduped

    def generate_candidates(self, base: str, limit: int | None = None) -> list[str]:
        """Join base + wordlist entries into full URLs, optionally limit."""
        urls = [join_url(base.rstrip("/"), w) for w in self.words]
        if limit is not None:
            urls = urls[:limit]
        return urls

    @staticmethod
    def is_soft_404(resp, baseline_body: str | None = None) -> bool:
        """Detect soft-404: 200 but body matches baseline 404 page (hash/length)."""
        if resp.status_code == 404:
            return True
        if resp.status_code != 200:
            return False
        if baseline_body is None:
            return False
        # Compare body hash and length delta
        body_hash = hashlib.sha256(resp.body.encode() if isinstance(resp.body, str) else resp.body).hexdigest()[:8]
        base_hash = hashlib.sha256(baseline_body.encode() if isinstance(baseline_body, str) else baseline_body).hexdigest()[:8]
        if body_hash == base_hash:
            return True
        # Length heuristic: if within 5% of baseline 404 length, likely soft-404
        if baseline_body and abs(len(resp.body) - len(baseline_body)) < max(50, len(baseline_body) * 0.05):
            # Check for common soft-404 phrases
            lower = resp.body.lower()[:500]
            if any(phrase in lower for phrase in ("not found", "404", "page not found", "does not exist")):
                return True
        return False

    # Backward compat: expose legacy lists for checks that still import them
    @property
    def debug_paths(self) -> list[str]:
        return list(_BUILTIN_DEBUG_PATHS)

    @property
    def backup_paths(self) -> list[str]:
        return list(_BUILTIN_BACKUP_PATHS)

    @property
    def map_paths(self) -> list[str]:
        return list(_BUILTIN_MAP_PATHS)

    @property
    def seed_paths(self) -> list[str]:
        return list(_BUILTIN_SEED_PATHS)
