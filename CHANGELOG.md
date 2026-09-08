# Changelog

## redveil-ui 0.2.0 — 2026-09-08

### added
- **Opt-in LAN auth (fail-closed)**: non-loopback bind without an API
  key refuses to start (`AuthConfigError`). Key resolution: env
  `REDVEIL_UI_API_KEY` → `~/.redveil-ui/.api_key` (0600) →
  `auth.api_key_hash` in config. `init` generates the key + LAN
  exposure warning (Y/n, `security.log` audit entry);
  `redveil-ui auth rotate-key` invalidates all sessions.
- **Auth flow**: HMAC session cookie (HttpOnly, SameSite=Strict,
  24 h TTL, conditional Secure) + `X-API-Key` header; `AuthMiddleware`
  short-circuits loopback; destructive actions (active profile, L3+,
  custom probes) require auth on LAN.
- **Scan control**: `POST /api/scans/{id}/start` + `/cancel`
  (spec §5.5 response matrix: 202 / 200 idempotent / 409 with
  timestamps); new `cancelled` terminal status across DB, SSE
  (`scan.cancelled`), and dashboard (amber badge, distinct banner,
  two-step Cancel button, History filter chip).
- **Reliability**: SQLite WAL + `busy_timeout=5000` +
  `synchronous=NORMAL` on every connection; `retry_on_lock`
  decorator on write-heavy paths; startup recovery sweep for orphan
  `'running'` scans.
- **Audit log**: append-only `audit_log` + `AuditLogMiddleware`
  (scan.create/start/cancel, probe.custom, target.delete) +
  `GET /api/audit` + `redveil-ui auth audit-rotate` (90 d retention,
  logs itself).
- **Security headers**: CSP + nosniff + DENY + no-referrer +
  Permissions-Policy on every response.
- **Rate limiting** (slowapi): 60/min default per IP, 5/min on login;
  `X-Forwarded-For` honored only from trusted proxies.
- **`/healthz`** now reports per-status scan counts
  (`scans_pending|running|completed|failed|cancelled`) + db check.
- **`POST /api/config/reset`** (replaces 501 stub): restores safety
  fields; 409 on non-loopback bind.
- **Findings page** (`/findings`) with the false-positive toggle
  deferred from 0.1.x (localStorage-persisted, muted "Suppressed"
  badge).

### changed
- Install snippet no longer hardcodes port 8000 (init picks the next
  free port; README explains how to check the configured port).
- Version strings unified to 0.2.0 across pyproject, package
  `__init__`, FastAPI app + `/api/info`, and frontend package.json.
- New dependency: `slowapi>=0.1.9`.

### migration (0.1.x → 0.2.0)
- No action required if you stay on localhost (default). Existing
  configs are valid; the `auth` config section is optional and its
  absence means loopback-only behavior. The `audit_log` table is
  created automatically on first startup; orphan `'running'` scans
  from a previous crash transition to `failed` once at startup.

Spec: `docs/superpowers/specs/2026-09-07-redveil-ui-0.2.0-design.md` ·
Plan: `docs/superpowers/plans/2026-09-07-redveil-ui-0.2.0.md`.

## 1.9.5 — 2026-09-01

### changed
- **CLI: comprehensive manpage-style `--help` output** (nmap-like).
  - Sections: TARGET SPECIFICATION, SCAN OPTIONS, AUTHORIZATION &
    ACTION GATE, REPORT COMMANDS, SAFETY PROFILES, DESTRUCTIVE LEVELS,
    EXAMPLES, EXIT CODES, SAFETY, DOCS.
  - Centered section headers (yellow) for visual clarity.
  - Tables for SAFETY PROFILES, DESTRUCTIVE LEVELS, EXIT CODES.
  - Triggered by `redveil --help` or `redveil -h` (no subcommand needed).
- `--version` / `-V` flag added (was missing).
- All `.md` cross-references in README use absolute GitHub URLs so
  they don't 404 on PyPI (which only hosts `README.md`).
- Bumped `__version__` to 1.9.5 (was stuck at 1.9.3).

## 1.9.3 — 2026-09-01

### added
- **DWYOR (Do With Your Own Risk) disclaimer** at the top of README as
  a `## ⚠️ DANGER ZONE` callout. New `DWYOR.md` with the full statement:
  authorized security testing only, system ownership or explicit
  written permission required, operator bears all legal/ethical
  liability, authors not responsible for misuse.
- **PEP 668 install warning** at the top of README: modern Linux distros
  (Debian 12+, Ubuntu 23.04+, Fedora 38+, etc.) block system-wide
  `pip install` with `externally-managed-environment`. Recommends
  `pipx` or `python -m venv`. Includes distro-specific commands
  (apt/dnf/pacman/zypper/brew).
- **Per-vuln destructive mapping** (`redveil/knowledge/destructive_levels.py`):
  - Each active check declares `max_destructive_level` and
    `recommended_max_level` + typical_actions.
  - Examples: `sqli-time-based` max=TAKEOVER, recommended=DATA_EXFILTRATION.
- 11 new tests for the per-vuln destructive mapping.

## 1.9.0 — 2026-09-01

### added
- **DestructiveLevel 1-6 scale** (replaces boolean `destructive`):
  - L1 data_exfiltration · L2 data_modification · L3 data_destruction
  - L4 persistence · L5 lateral_movement · L6 takeover
- **Tiered confirmation** for destructive actions:
  - L1-2: simple Y/N
  - L3+: user must **type the exact word** (`CONFIRM`, `CONFIRM-LEVEL-4`, etc.)
    or the plan's `confirm_word` (e.g. `rm-rf`, `drop-table`)
- **`max_destructive_level` config field** (accepts short form `L1`..`L6`):
  - operator's ceiling. Plans above are denied even with `allow_destructive: true`
  - default `2` (data_modification allowed, destruction blocked)
- **Per-check `destructive_level` + `confirm_word` fields** in `ActionPlan`:
  - XSS, SQLi, CMDi, SSRF, path-traversal, BOLA, BFLA wired
- **ActionGate.audit_log()**: JSON-serializable decision history for
  audit reports
- **ActionGate tiered prompts** in interactive mode:
  - level 1-2: standard Y/N
  - level 3+: prominent warning + "Type CONFIRM[-LEVEL-N]"
- 19 new tests for DestructiveLevel + tiered confirmation
- 11 new tests for per-vuln destructive mapping

## 1.8.0 — 2026-09-01

### added
- `redveil/validation/environment.py`: Environment enum + profile
- `redveil/validation/replay.py`: ReplayRecipe + ReplayEngine (Wave 3)
- `redveil/validation/flakiness.py`: FlakinessDetector (Wave 4)
- `redveil/validation/oracle.py`: Oracle enum + Signal (Wave 2)
- `redveil/validation/confidence.py`: ConfidenceScorer with multi-signal (Wave 2)
- `redveil/validation/risk.py`: Risk enum + ActionPlan (Wave 7)
- `redveil/validation/gate.py`: ActionGate with 3 modes (Wave 7-8)
- `redveil/attack_surface/`: ApplicationModel + BehaviorModel (Phase 2)
- `redveil/behavior/`: State + Transitions + Hypotheses + Planner (Phase 2)
- Wave 6: environment awareness + uncertainty propagation
- 1070 → 1089 tests passing

## 1.0.0 — 2026-09-01

first public release. 17 check plugins, 920 tests.

### safety
- no destructive payloads. runtime assertions in every active check
- no data extraction payloads (SQLi is time-based only)
- no internal IP targeting (SSRF uses operator-configured OOB domain only)
- ACTIVE profile requires `authorization.acknowledged_safety_terms=true`
- evidence sanitizer redacts cookies, JWTs, AWS keys, GitHub tokens, Stripe keys, credit cards, emails

see [SECURITY.md](SECURITY.md) for the full model.
