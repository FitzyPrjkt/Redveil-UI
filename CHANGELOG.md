# Changelog

## redveil-ui 0.6.1 — 2026-09-11

### removed
- **AI Gateway + AI Chat**: `ui/frontend/src/app/ai` + `redveil_ui/api/routes/ai.py` `/api/ai/*` removed from sidebar and API (was `openai_compatible` `https://agentrouter.org/v1` `glm-5.3`/`gpt-5.6-sol` with `api_key_env`). Destructive authorization (`POST /api/scans` `max_destructive_level L1-L6` `allow_destructive` + `active_testing` gate) remains intact.
- **OpenAPI sidebar entry**: `ui/frontend/src/app/openapi` page still exists but removed from `Sidebar` `Configure` section per request (API `POST /api/openapi` still available if needed).

### changed
- `pyproject 0.6.0→0.6.1`, `ui/frontend 0.6.0→0.6.1`, `api/main 0.6.0→0.6.1` — dark theme `checkbox #18181b checked #0284c7` + `button sky-600` verified `playwright 3/3`.
- `redveil_ui/scanner.py` `LimitsConfig max_requests 3000` for `active/L3-L6` (was 500, caused `max_requests limit` on `sqli 640 + command 1190`).

## redveil-ui 0.6.0 — 2026-09-10

### added
- **AI Tools E1**: `ai/tools/registry.py` 6 tools `inspect_endpoint/search_findings/replay_request/compare_responses/run_check/inspect_browser` + `ai/safety.py` guard `scope/auth/gate/limits/block exec` + `ai/tools/loop.py` bounded `tool_calls` loop `max 3` `tool_calling` capability check, `POST /api/ai/tools/execute` + safety-gated `denied:true`, `tests/test_ai_tools 10 passed`.
- **AI Browser E2**: `ai/browser/observation.py` `collect_observations` `playwright` `screenshot+DOM+a11y+console+network` → `BrowserObservation` `dom_hash_sink/postMessage/prototype_pollution` heuristics + `detect_dom_xss_from_observation` `location.hash→innerHTML` `CWE-79` high, `POST /api/ai/browser/observe` scope-checked, `tests/test_ai_browser 4 passed` (incl. `hash→innerHTML` + `postMessage`).
- **Local + Cost E3**: `openai_compatible http://localhost:11434/v1` generic (no code), `ai/cost.py TokenBudget {max_tokens 50k, max_requests 20, context_limit 8k}` `can_request/record/truncate/cache/rate` + `ai/privacy.py redact_for_ai` deep `Authorization/JWT` + `truncate`, `GET /api/ai/cost`, `POST /api/ai/tools/*` + `GET /api/ai/cost`, `tests/test_ai_cost 6 passed`.

### changed
- `pyproject 0.5.0→0.6.0`, `src/redveil 1.9.8→1.9.9` (+ `redveil>=1.9.9`), `ui/frontend 0.5.0→0.6.0`, `api/main 0.5.0→0.6.0`.

## redveil-ui 0.5.0 — 2026-09-10

### added
- **AI Analysis D1**: `ai/analysis.py` `explain_finding(finding,evidence,ai_config)` read-only sanitized (`Authorization/Cookie/JWT→[REDACTED]` deep), `ExplainOut` JSON schema + `build_explain_messages`, `POST /api/findings/{wpoc_id}/explain` (DB `AiConfigStore` + `Evidence` limit 5), failure-isolated `ok False` not crash, `tests/test_ai_analysis 7 passed`.
- **AI Hypothesis D2**: `ai/context.py build_context` (Evidence 25f+Model→sanitized 6000 chars) + `ai/hypothesis.py generate_hypotheses` `SecurityHypothesisOut` → `Hypothesis(InvariantKind)` `object_ownership/function_level/...` via `planner.py` invariant, `POST /api/ai/hypothesize {scan_id, max_hypotheses}` DB findings/evidence context, structured JSON `{"hypotheses":[{invariant,target_endpoint,reasoning,confidence,recommended_check}]}` validated, `tests/test_ai_hypothesis 9 passed`.
- **Capability routing D3**: `ai/routing.py route_for_task("fast|reasoning|vision|explain|hypothesis")` + `supports_capability(tool_calling/vision/structured)` fallback to explicit `AiCapabilities` or defaults, `AiConfig.models {fast, reasoning, vision}` per-task provider override, `tests/test_ai_routing 7 passed`.
- **Privacy**: `ai/analysis _deep` redaction + `sanitizer` reuse, `ai/context _sanitize_headers`, capability best-effort `/models` fallback explicit (clarification 1), failure isolation `ai.enabled=false → scanner tetap`.

### changed
- `pyproject 0.4.0→0.5.0`, `src/redveil 1.9.7→1.9.8` (+ `redveil>=1.9.8`), `ui/frontend 0.4.0→0.5.0`, `api/main 0.4.0→0.5.0`.

## redveil-ui 0.4.0 — 2026-09-10

### added
- **Headless crawler (C1)**: `discovery/headless.py` `HeadlessCrawler`/`HeadlessConfig` via `playwright` `page.goto(networkidle)` + `evaluate` JS extraction + `request` capture for SPA `→ /api/data`, `AttackSurfaceMapper` auto headless when `headless:true`, `is_headless_available()` guard + failure-isolated `pip install playwright && playwright install chromium`.
- **Concurrent orchestrator (C2)**: `core/orchestrator.py` `Semaphore(max_concurrent_requests)` + `asyncio.gather` per-phase, `evidence_store`+`findings` `asyncio.Lock` for `dedup` safety, `http/rate_limit.PerHostLimiter` per-host `TokenBucket` dict, `HttpClient` dual acquire `per_host + global`.
- **Evidence DB index (C3)**: `redveil_ui/api/models.Evidence` + `persistence/evidence_model.EvidenceRow`/`evidence_index.EvidenceIndex` indexed `endpoint/check_id/waf_detected/scan_id`, `scanner._write_evidence_rows` + `routes/scans GET /evidence` DB-first indexed query (<100ms 10k), fallback to file/projected, `Base.create_all` auto.

### changed
- `pyproject 0.3.0→0.4.0`, `src/redveil 1.9.6→1.9.7` (+ `redveil>=1.9.7`), `ui/frontend 0.3.0→0.4.0`, `api/main 0.3.0→0.4.0`, `config.headless bool + headless_config dict`.

## redveil-ui 0.3.0 — 2026-09-10

### added
- **Capability-first scan tuning**: `enabled_checks[]` allowlist via `RedVeilConfig.enabled_checks`, `cli scan --checks xss,sqli --checks-file`, `POST /api/scans {enabled_checks}` + UI `targets/new` multiselect (reuse `GET /api/checks`).
- **WordlistManager (A2)**: curated builtin 91→811 with extensions, soft-404 hash/length/phrase, `SecLists from_file`, `disclosure` random baseline, `mapper` seeds.
- **OpenAPI parser (A3)**: `openapi.yaml/json` 3.x+2.0 → `ApplicationModel`, `config openapi_spec 200KB`, `cli --openapi`, `POST /api/scans {openapi_spec}`.
- **Raw Repeater (A4)**: `POST /api/replay/custom {method,url,headers,body,samples}` → `ReplayEngine` `Reproducible/Flaky`, scope 403 rate-limited.
- **Generic AI Gateway P1 (A5)**: provider-agnostic `AiConfig {enabled, provider:{type,protocol,base_url,api_key,api_key_env,model,headers,capabilities}, models:{fast,reasoning,vision}}` via `httpx` + `sanitizer`, `detect_capabilities()` best-effort `/v1/models` fallback, adapters OpenAI/Anthropic/OpenAI-compatible (`https://any-proxy.web.id/v1`, `http://localhost:11434/v1`), failure-isolated.
- **OAST provider abstraction (B3)**: `validation/oast.py OASTProvider ABC + OastConfig`, `InteractshOASTProvider` default `https://oast.fun`, `config oast {provider,base_url,api_key,api_key_env}`, `SSRFCheck` auto `register → poll(1s retry) → CONFIRMED` via `build_oast_provider`, failure-isolated LIKELY fallback.
- **Session rules (B1)**: `http/session_rules.py` CSRF regex extract `from body/header/json` → inject `header/cookie` per scope TTL 5m, `401/403 re-auth` `POST login_url` Set-Cookie retry once, `HttpClient` `send()` pre-hook + `send_raw()` bypass.
- **Intruder full (B2)**: `probe/runner.py` `attack_mode sniper|battering_ram|pitchfork|cluster_bomb` + `payloads2/position2` + `payload_processors [url_encode,base64,hex,html_encode,prefix:,suffix:,upper/lower]`.
- **GraphQL fuzz (B4)**: `checks/graphql.py` introspection `→ types → fuzz` via `_FUZZ_QUERIES {users, user(id:1), me, profile, accounts}` minimal `id` only, `_is_fuzz_success` + `graphql_fuzz_bola` kind `CONFIRMED HIGH` `CWE-639` BOLA, `collect_evidence BODY_DIFF` + `assess HIGH`.
- **DESIGN.md compliance (P0)**: `low` accent `bg-sky`, `stat surface-1 no border 8px`, `tsc clean`, `Playwright 13/14`.

### changed
- `pyproject.toml` `redveil-ui 0.2.0 → 0.3.0`, `src/redveil 1.9.5 → 1.9.6`, `ui/frontend 0.2.0 → 0.3.0`.
- `ScopeController` + `Gate` + `Limits` preserved through `enabled_checks` filtering and OAST/GraphQL fuzz.

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
  short-circuits loopback (XFF only from trusted proxies) and
  validates hash-only installs (`auth.api_key_hash` in config);
  destructive actions (active profile, L3+, custom probes, target
  deletion, scan start of a destructive row) require auth on LAN.
- **Scan control**: `POST /api/scans/{id}/start` + `/cancel`
  (spec §5.5 response matrix: 202 Accepted on dispatch, 200 with
  `idempotent: true` for an already-satisfied action, 409 with
  timestamps for terminal states); new `cancelled` terminal status
  across DB, SSE (`scan.cancelled`), and dashboard (amber badge,
  distinct banner, two-step Cancel button, History filter chip).
- **Reliability**: SQLite WAL + `busy_timeout=5000` +
  `synchronous=NORMAL` on every connection; `retry_on_lock`
  decorator on write-heavy paths; startup recovery sweep for orphan
  `'running'` scans.
- **Audit log**: append-only `audit_log` + `AuditLogMiddleware`
  (scan.create/start/cancel, probe.custom, target.delete; outcomes
  allowed / denied / not_found) +
  `GET /api/audit` + `redveil-ui auth audit-rotate` (90 d retention,
  logs itself).
- **Security headers**: CSP + nosniff + DENY + no-referrer +
  Permissions-Policy on every response.
- **Rate limiting** (slowapi): 60/min default per IP on every route
  (opt out with `REDVEIL_RATE_LIMIT_DEFAULT=0/minute`), 5/min on
  login; `X-Forwarded-For` honored only from trusted proxies
  (`REDVEIL_TRUSTED_PROXIES`, default loopback).
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
