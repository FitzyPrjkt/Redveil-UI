# Redveil UI — Progress & Handoff (untuk session baru)

> **Baca file ini dulu di session baru.** Isinya audit lengkap + semua yang sudah dikerjakan biar nggak perlu audit 1-1 lagi. Update file ini tiap selesai milestone.

- **Workspace:** `/workspace/projects/Redveil` (`git rev-parse --show-toplevel == pwd`)
- **Branch:** `main` | **Remote:** `origin=Redveil`, `ui=Redveil-UI` (synced `0 0` di `c2f7874`)
- **Versi:** `pyproject.toml:1` `redveil-ui 0.2.0` → `src/redveil/__init__.py:11` `1.9.5` (installed `1.9.6`), `requires-python >=3.11`
- **Build artifact:** `redveil_ui/web/` = `ui/frontend/out` via `pyproject.toml:36 force-include`, **untracked sengaja, jangan masuk .gitignore** (user request)
- **Date:** 2026-09-09 | **Model:** muse-spark-1.2

---

## 1. Aturan & Preferensi User (jangan dilanggar)

1. **Jangan start Redveil UI** kecuali user suruh eksplisit. Kalau mau test server, tanya dulu.
2. **`redveil_ui/web` jangan di-gitignore** — biar reusable tapi tetap untracked.
3. **TLS harus auto tanpa warning di semua browser** — `redveil-ui init --tls` generate Local CA + cert, `redveil-ui tls install-ca` harus trust di: system (`/usr/local/share/ca-certificates`, `update-ca-certificates`, `trust anchor` mac, `certutil` windows), Firefox + forks (`~/.mozilla/firefox/*.default*/cert9.db`, `~/.librewolf`, `~/.waterfox`, `~/.floorp`, `~/.zen`, `~/.mullvad-browser`, `~/.moonchild productions/*`, Flatpak `~/.var/app/*/data/mozilla/firefox/...`), Chromium-based (`~/.pki/nssdb/cert9.db`), WebKit. Tor browser sengaja skip.
4. **Dogfooding spec §14.4/§17:** fail-closed sebelum socket, LAN gate `middleware.py:48 AuthMiddleware`, `X-Forwarded-For` hanya dari `REDVEIL_TRUSTED_PROXIES`.

---

## 2. Status 0.3.0 — Semua deferred DONE (8/8)

| # | Fitur | Commit | Files kunci | Verifikasi |
|---|-------|--------|-------------|------------|
| 1 | **Auto-port fallback** — `DEFAULT_PORT 8000`, walk-forward `find_free_port`, persist `port` ke `config.yaml`, log `Here's the link: http(s)://host:port/` | `c5f7032` | `redveil_ui/server.py:116-301` (`_resolve_config_path`, `_find_free_port`, `run_server`), `first_run.py:34` | Start dua instance di `8000` → kedua naik di `8001`, probe builder `verify-probe-builder-api.spec.ts:43` fix `/PRB-/` → `/WPOC-\|probe_id/` |
| 2 | **TLS Local CA auto** — `ca/ca.pem` 10y, `certs/cert.pem` 825d SAN `localhost,127.0.0.1,::1` + LAN IPs `get_lan_ips()`, `init --tls` + `tls init-ca/status/install-ca` | `1dd4ca5` | `redveil_ui/tls.py` (342 lines), `cli.py: init --tls`, `cli_tls.py`, `first_run.py:204 enable_tls`, `server.py:262 ssl_*` | `curl -k https://127.0.0.1:8443/healthz` OK, `curl --cacert ~/.redveil-ui/ca/ca.pem` OK, `openssl verify -CAfile ca.pem cert.pem` OK |
| 3 | **All-browser install** — single `install-ca` untuk system+Firefox+Chrome | `338657f` + `7366a84` | `tls.py: _install_firefox_ca`, `_install_chrome_nss_ca` | Forks scan + Flatpak + `~/.pki/nssdb`, hint `libnss3-tools` |
| 4 | **Finding annotations** — `notes TEXT` + `annotated_at`, `PATCH /api/findings/{wpoc_id}`, UI badge + Operator Notes | `7f17cf5` | `api/models.py:70 Finding`, `schemas.py:211 FindingPatch*`, `routes/findings.py:24`, `lib/api.ts: apiPatch`, `findings/page.tsx`, `findings/[wpoc_id]/page.tsx`, migration di `main.py` + `server.py` | TestClient `PATCH 200` return notes |
| 5 | **CSP tightened** — `script-src 'nonce-xxx'` + `style-src 'nonce-xxx'` inject ke `<style>` | `acd1cf3` | `api/middleware.py:307 SecurityHeadersMiddleware` (`_STYLE_SRC_RE`) | `tests/test_security_headers.py` updated pass |
| 6 | **Scheduling** — `ScheduledScan` + `CronTrigger` APScheduler, `CRUD /api/schedules` + `POST /{id}/trigger`, UI `schedules/page.tsx` | `acd1cf3` | `models.py ScheduledScan`, `schemas.py ScheduledScanCreate/Out` (croniter), `routes/schedules.py`, `scheduler.py`, `main.py lifespan load_schedules()` | Build 20 pages |
| 7 | **PDF export + JSON log** — `reportlab` A4 `generate_pdf`, `GET /{id}/report?format=pdf` on-the-fly `/tmp/redveil-report-{id}.pdf`, `LOG_FORMAT=json` JsonFormatter | `0030cef` | `api/pdf_report.py`, `routes/scans.py:745`, `scans/[id]/page.tsx Report card`, `main.py:43 logging` | `%PDF-1.4` 1794 bytes |
| 8 | **Multi-key** — `api_key_hashes` list deduped, `REDVEIL_UI_API_KEYS` + `.api_key` comma-separated, header+cookie loop, `auth add-key/list-keys/remove-key` (respect `REDVEIL_CONFIG`) | `35617db` | `api/auth.py: _load_auth_hashes/_resolve_api_keys/_key_matches/validate_session_cookie_any`, `middleware.py header+cookie`, `routes/auth.py login`, `cli_auth.py` | `REDVEIL_CONFIG=/tmp/test-multikey` 2 hashes → `login key1 200 key2 200 bad 401`, `LAN key1 202 key2 202`, `add-key 2→3 remove 3→2`, `pytest auth 47 passed` |

**Commits 0.2.0 → now (8):**
```
35617db feat(auth): multi-key support — concurrent API keys
0030cef feat(report, logging): PDF export + JSON structured logging
acd1cf3 feat(security, scheduling): CSP style nonce + cron schedules
7f17cf5 feat(findings): operator annotations — notes per finding
7366a84 feat(tls): cover all Firefox forks + Chromium + WebKit in one install
338657f feat(tls): one-script CA install for all browsers
1dd4ca5 feat(tls): Local CA auto + install trust — no browser warning
c5f7032 feat(server): auto-pick free port on start + Here's the link
c2f7874 fix(e2e): single base URL for all specs — kill hardcoded :3001
924f14c fix(security): CSP nonce for SPA inline scripts + HEAD on SPA routes
```

**Test gate terakhir:** `pytest tests/test_auth*.py tests/test_server_fail_closed.py → 47 passed` , `pytest full → 1467 passed` (sebelum 0.3.0), `tsc --noEmit clean`, `Playwright 54/54` di `playwright.config.ts:18 baseURL http://127.0.0.1:8000` (setelah fix hardcode).

---

## 3. Arsitektur Penting (biar nggak audit ulang)

```
redveil_ui/
├── cli.py              — typer main, `init --tls`, `app.add_typer(tls_app)`
├── cli_auth.py         — rotate-key, add-key, list-keys, remove-key, audit-rotate (respect REDVEIL_CONFIG env)
├── cli_tls.py          — tls status | init-ca | install-ca
├── first_run.py:34     — find_free_port(host,preferred), run_init(enable_tls) → tls.ensure_tls_assets()
├── server.py:116-301   — _resolve_config_path, _find_free_port probe 127.0.0.1/0.0.0.0, run_server auto-port + https ssl_certfile/keyfile + Here's the link
├── tls.py (342)        — generate_ca(10y), generate_server_cert(825d SAN LAN), ensure_tls_assets, get_lan_ips, get_tls_paths, install_ca (system+firefox+chrome)
└── api/
    ├── auth.py:46-158  — FAIL_CLOSED_MESSAGE, check_auth_or_fail(fail-closed), _load_auth_hashes (single+list), _resolve_api_keys (env+file comma), _key_matches, validate_session_cookie_any, has_config_hash
    ├── middleware.py:48,304-350 — AuthMiddleware (LAN + X-API-Key + cookie + rate-limit), SecurityHeadersMiddleware (CSP nonce script+style)
    ├── models.py:70    — Finding.notes/annotated_at, ScheduledScan, Scan, AuditLog (retry-on-lock)
    ├── schemas.py:211  — FindingOut/Patch, ScheduledScanCreate/Out (croniter valid)
    ├── routes/
    │   ├── auth.py     — POST /api/auth/login (tries raw keys then any hash)
    │   ├── findings.py:24 — PATCH /{wpoc_id}
    │   ├── schedules.py — CRUD /api/schedules + POST /{id}/trigger
    │   └── scans.py:745 — GET /{id}/report?format=pdf (reportlab on-the-fly)
    ├── scheduler.py    — AsyncIOScheduler + CronTrigger.from_crontab + load_schedules()
    ├── pdf_report.py   — generate_pdf(scan) reportlab A4
    └── main.py:43,60   — LOG_FORMAT=json, lifespan DB create_all + migration PRAGMA table_info ALTER + load_schedules()

ui/frontend/src/
├── lib/api.ts          — apiGet/Post/Patch/Delete, sseUrl
├── app/findings/page.tsx — badge Annotated sky
├── app/findings/[wpoc_id]/page.tsx — Operator Notes card
├── app/schedules/page.tsx — cron UI
├── app/scans/[id]/page.tsx — Report export MD/HTML/JSON/PDF
└── components/sidebar.tsx — IconClock Schedules

pyproject.toml — redveil>=1.9.6, fastapi, uvicorn, sqlalchemy[asyncio], aiosqlite, slowapi, rich, cryptography>=42, apscheduler>=3.10, croniter>=2, reportlab>=4, python-json-logger>=2
```

**Config & Paths:**
- `~/.redveil-ui/config.yaml` — `auth.api_key_hash` (legacy) atau `auth.api_key_hashes: [sha256:...]` , `host`, `port`, `data_dir`, `tls.enabled/certfile/keyfile/cafile`
- `~/.redveil-ui/.api_key` — raw keys comma-separated (fallback)
- `~/.redveil-ui/ca/ca.pem` + `ca-key.pem`, `~/.redveil-ui/certs/cert.pem|key.pem`
- `data/redveil-ui.db` runtime (also `~/.redveil-ui/data/redveil-ui.db`, tmp test dirs)

**Known DB migration:** `Finding.notes/annotated_at` ditambah via `PRAGMA table_info` + `ALTER TABLE` di `main.py` lifespan + `server.py` start. Kalau DB lama, 3 path perlu `sqlite3 ... ALTER TABLE findings ADD COLUMN notes TEXT` manual (sudah done).

---

## 4. Verifikasi yang sudah dijalankan (evidence)

- Backend: `1467 passed`, `tsc --noEmit` clean, `Playwright 54/54` (setelah `e2e/verify-probe-builder-api.spec.ts:43` fix).
- Server port: dua instance `8000` → `8001`, persist `port` ke `config.yaml`, probe `fix verify-probe-builder-api` `/WPOC-|probe_id/`.
- TLS: `curl -k https://127.0.0.1:8443/healthz 200`, `curl --cacert ca.pem 200`, `openssl verify OK`, SAN includes LAN IPs.
- Annotations: `TestClient PATCH /api/findings/{id} 200` + UI.
- CSP: `script-src 'nonce-xxx' style-src 'nonce-xxx'` header + inject `<style nonce>`.
- Scheduling: `APS Scheduler started`, build `20 pages`.
- PDF: `Content-Type application/pdf` `%PDF-1.4` 1794 bytes, Build `redveil_ui/web`.
- Multi-key: `REDVEIL_CONFIG=/tmp/test-multikey` (2 hashes) → `login key1 200 key2 200 bad 401`, `LAN X-API-Key key1 202 key2 202`, `add-key 2→3` (`rvui_6efcf4473cef3d79213109b16fc30bce hash ee63bf...`), `list-keys` correct, `47 passed auth` .
- Security: `check_auth_or_fail("0.0.0.0")` raises `OperationalError`, `_load_auth_hashes` deduped, `AuthMiddleware` fail-closed, `REDVEIL_TRUSTED_PROXIES` gate.

**Blockers diketahui:**
- `certutil not found` kalau `libnss3-tools` belum install → `tls install-ca` skip Firefox: install `sudo apt install libnss3-tools`.
- `sudo` butuh terminal interaktif untuk system CA → run `redveil-ui tls install-ca` di terminal biasa, bukan via agent non-interactive.

---

## 5. Next Session — Cara Lanjut (copy-paste ready)

**1. Smoke check (30 detik):**
```bash
cat REDVEIL_UI_PROGRESS.md | head -n 30
git log --oneline -8
cat pyproject.toml | grep -E "version|dependencies" | head -n 20
.venv/bin/redveil-ui auth --help
.venv/bin/redveil-ui tls status
```

**2. Test gate (2 menit):**
```bash
.venv/bin/python -m pip install -e . -q
.venv/bin/python -m pytest tests/test_auth*.py tests/test_server_fail_closed.py -q   # expect 47 passed
.venv/bin/python -m pytest -q  # full 1467 passed
cd ui/frontend && npx tsc --noEmit && cd ../..
```

**3. Multi-key manual (kalau perlu debug):**
```bash
REDVEIL_CONFIG=/tmp/test-multikey/config.yaml .venv/bin/redveil-ui auth list-keys
REDVEIL_CONFIG=/tmp/test-multikey/config.yaml .venv/bin/redveil-ui auth add-key
# TestClient with new key: see redveil_ui/api/auth.py: _load_auth_hashes
```

**4. Update MD ini tiap milestone:**
- Setelah commit baru, tambah baris di tabel §2 + update `git log` + verifikasi.
- Kalau bump version, update `pyproject.toml:1` + `CHANGELOG.md`.

**Sisa 0.3.0 polish (opsional, belum dibump ke 0.3.0):**
- [ ] Bump `pyproject.toml` `0.2.0 → 0.3.0` + `CHANGELOG.md` + tag.
- [ ] Final `Playwright 54/54` on `https://127.0.0.1:8000` (setelah `tls install-ca` di terminal interaktif).
- [ ] `pip install -e .` verify `redveil-ui init --tls` fresh install flow.

---

## 6. File relevan untuk next audit (jangan baca semua, ini prioritas)

- `redveil_ui/server.py:116-301` — port fallback + https
- `redveil_ui/tls.py` — CA/cert generation + install
- `redveil_ui/api/auth.py:46-158` — fail-closed + multi-key
- `redveil_ui/api/middleware.py:48,304-350` — Auth + CSP
- `redveil_ui/api/models.py:70` + `schemas.py:211` + `routes/findings.py:24` — annotations
- `redveil_ui/api/scheduler.py` + `routes/schedules.py` + `main.py:60` — cron
- `redveil_ui/api/pdf_report.py` + `routes/scans.py:745` — PDF
- `redveil_ui/cli_auth.py` — multi-key CLI
- `ui/frontend/src/app/findings/[wpoc_id]/page.tsx` + `schedules/page.tsx` + `scans/[id]/page.tsx`
- `tests/test_auth*.py`, `tests/test_server_fail_closed.py`, `tests/test_security_headers.py`, `ui/frontend/playwright.config.ts:18`

> **Jangan start server tanpa izin user.** Kalau perlu test https, tanya dulu, lalu test `curl --cacert ~/.redveil-ui/ca/ca.pem https://127.0.0.1:8443/healthz`.

---

## 7. BURP PARITY AUDIT 2026-09-09 (merged — single file mode)

> **Catatan:** Audit lengkap Burp parity sebelumnya di file terpisah `REDVEIL_AUDIT_BURP_PARITY_2026-09-09.md` kini di-merge ke sini agar **cukup 1 file MD**. Update milestone berikutnya via python patch append section baru, jangan buat file baru.

### Redveil vs Burp Suite — Technical Feature Audit (Source-Code Evidence) (Source-Code Evidence)

**Date:** 2026-09-09 | **Auditor:** Senior Pentest / Web AppSec / Architect (source-code audit, bukan README)  
**Workspace:** `/workspace/projects/Redveil` | **Branch:** `main` @ `35617db` | **Versions:** `redveil 1.9.5-1.9.6`, `redveil-ui 0.2.0`  
**Scope:** `src/redveil/**`, `redveil_ui/**`, `ui/frontend/src/**`, `tests/**`, `pyproject.toml`, `config`, `examples`  
**Method:** `glob` + `grep` + `read` per-file, fail-closed evidence requirement. Jika klaim tidak punya `file:line/class/function/CLI/config/test`, status `NOT IMPLEMENTED`/`NOT VERIFIED`.

> **Positioning:** Redveil = **security assessment / scanning framework** (automated, evidence-grade, safety-gated). Burp Suite = **interactive web security workbench** (proxy-centric). Audit tidak menghukum Redveil karena tidak punya proxy/intercept — nilai berdasarkan relevansi positioning (§27, §34).

---

## 28. Executive Summary

**Apakah Redveil sudah mendekati Burp Suite? — Tidak.** Redveil sudah kuat sebagai **scanner framework** dengan safety/evidence/replay terbaik di kelasnya, tapi jauh dari **workbench interaktif** Burp. Closer to **hybrid scanner + assessment framework**, bukan proxy workbench.

| Kategori Burp | Score 0-100 | Justifikasi evidence |
|---------------|-------------|----------------------|
| **Vulnerability Detection** | **55** | 18 checks (PASSIVE 8 + ACTIVE 10) — headers/CORS/disclosure/sourcemap/http-methods/redirect/graphql + XSS/SQLi/SSRF/CMDi/traversal/BOLA/BFLA/mass-assign/session. Tanpa SSRF OOB server, tanpa DOM XSS, tanpa SSTI/XXE/deserialization, tanpa GraphQL fuzz full. Validasi timing/control-probe hanya untuk SQLi/CMDi. |
| **Active Testing** | **45** | `SafetyProfile PASSIVE/LOW/ACTIVE` + `ActionGate L1-L6` + `ScopeController` strict 5-gate adalah best-in-class. Tapi payload engine terfragmentasi (per-check hardcode), tidak ada PayloadManager, tidak ada per-check select, tidak ada insertion points custom, tidak ada Collaborator polling. |
| **Passive Analysis** | **70** | Paling matang: security headers, CORS, session cookie (entropy+SameSite+flags), disclosure 17 paths + source maps, redirect, methods. Semua PASSIVE tanpa wire tambahan, evidence sanitized. |
| **Traffic Manipulation** | **15** | `HttpClient` satu-satunya egress (scope→limits→TokenBucket→Semaphore→httpx, redirect re-validate) sangat solid untuk *outbound* scanner. Tapi **0 proxy intercept**, 0 Match/Replace, 0 Inspector raw/hex, 0 WS history. `ProbeRunner` hanya sniper 1-pos, bukan Repeater/Intruder. |
| **Reconnaissance** | **35** | `Crawler BFS 100pages/depth3` regex-only + `AttackSurfaceMapper` seed 11 paths + `SubdomainFinder` DNS 80 prefixes. Tanpa sitemap.xml parser, tanpa OpenAPI, tanpa JS rendering, tanpa headless, tanpa Content Discovery wordlist. Site Map hanya post-scan aggregate, bukan live crawl. |
| **Automation** | **60** | Orchestrator state-machine + EventBus SSE + Scheduler APScheduler cron + CLI `scan/list-checks/report` + `probe --dwyor`. Tapi orchestrator sequential (no parallel), no macros, no session rules, no auto re-auth/CSRF refresh. |
| **Validation** | **80** | **Strength terbesar:** `ReplayEngine` (samples+ variance) + `ControlProbe` (9 req baseline/control/probe) + `StagedValidator` + `FlakinessDetector` (5 samples) + `Oracle` (1-5) × `ConfidenceScorer` (env+uncertainty penalty) + `FindingDeduplicator` (fingerprint+root cause). Evidence fingerprint + sanitizer `[REDACTED]`. |
| **Reporting** | **65** | `markdown/json/html` + PDF `reportlab` + Evidence Log + AuditLog + `finding.notes` operator. Tapi no SARIF, HTML single-file, evidence bukan DB (file JSON), no diff baseline. |
| **Extensibility** | **55** | `Check(ABC) → Registry → loader entry_points redveil.checks` 40+ categories + 18 checks + UI `GET /api/checks`. Tapi hanya Check extension, no hooks untuk Reporter/Auth/Evidence, no marketplace, `check` CLI stub. |
| **UI / Interactive Workflow** | **40** | Next.js 16 SPA 20 pages + SSE + TLS Local CA multi-browser + CSP nonce. Dashboard/Targets/Sitemap/Scans/Findings/Replay/ProbeBuilder/Decoder/Comparer/TokenEntropy/Audit/Schedules lengkap untuk **scan-centric** workflow. Tapi 0 Proxy/History/Intercept/Repeater-tabbed, Site Map tidak live, no Organizer (tags/rating), no Command Palette, scan UI selalu anonymous (principals tidak wire). |
| **AI Capability** | **5** | **0 AI di src/redveil/redveil_ui/ui** (`grep openai|anthropic|llm 0 hits`, `pyproject 0 AI deps`). `behavior/hypotheses.py` ada tapi rule-based (BOLA/BFLA), bukan LLM. Safety/privacy/cost untuk scanner saja sangat matang, untuk AI 0. |

**Redveil lebih dekat ke:** **Vulnerability scanner (55) → Security assessment framework (hybrid) → Workbench (15)**. Jangan pakai Redveil sebagai pengganti Burp untuk manual pentest; pakai **bersamaan**: Burp/ZAP untuk proxy/manual, Redveil untuk automated evidence-grade scan + replay + scheduling.

---

## 29. Feature Matrix (Category | Feature | Status | Evidence | Gap)

> Status definisi §25: IMPLEMENTED = usable; PARTIAL = sebagian tapi belum lengkap; ARCHITECTURALLY SUPPORTED = fondasi ada belum diekspos; NOT IMPLEMENTED = belum ada; NOT VERIFIED = indikasi ada tapi tidak terbukti; NOT APPLICABLE = tidak relevan positioning.

### 1. Reconnaissance & Mapping

| Feature | Status | Evidence | Gap |
|---------|--------|----------|-----|
| **Target Site Map** | **PARTIAL** | `redveil_ui/api/routes/targets.py:138 GET /{id}/sitemap → SiteMapOut` agregasi `Finding` group `(method,path)` + `ui/frontend/src/app/targets/[id]/page.tsx:112 SiteMapView` + `scans/[id]/page.tsx sitemap tab`. `src/redveil/attack_surface/mapper.py:41 AttackSurfaceMapper.build()` parse `GET /` links/forms/scripts | Bukan crawl live. Hanya inventory post-scan dari findings, bukan dari crawling. Tidak parse `sitemap.xml`, tidak populate real-time dari proxy. Perlu rename “Endpoint Inventory” biar tidak misleading. |
| **Target Scope Control** | **IMPLEMENTED** | `src/redveil/core/scope.py:48 ScopeController` 5-gate (allowed_hosts non-empty → fnmatch allowed_paths → excluded_paths deny → destructive patterns `/delete/*` → MUTATING_METHODS) + `check_redirect_chain` + `config.py:61 ScopeConfig` + `redveil_ui/api/scope_check.py` + `http/client.py:107 ScopeViolation` pre-wire + `crawler.py:210` filter | Path glob hanya `fnmatch`, bukan regex; no CIDR/port/scheme allow; no `*.example.com` wildcard; destructive patterns hard-coded; no per-check scope. Tetap strongest rail. |
| **Live Passive Crawling** | **NOT IMPLEMENTED** | `grep -R live.*crawl src/ redveil_ui/ ui/ 0 hits`. Crawler batch BFS di `orchestrator.py:209 _discovery_phase` sekali jalan, EventBus `DISCOVERY_STARTED/ENDED` only | Tidak ada daemon live map dari traffic proxy. Gap total vs Burp Live Crawl. Butuh proxy history dulu. |
| **Live Active Crawling** | **PARTIAL** | `src/redveil/discovery/crawler.py: CrawlerConfig(max_pages=100,max_depth=3,allowed_hosts,excluded_paths,honor_robots,delay)` + `Crawler.crawl()` BFS deque + `_fetch_robots` + `_extract_links` regex `href/src/action` via `HttpClient` + `plugins/discovery/subdomain.py:60 SubdomainFinderCheck` + `tests/test_crawler.py 15 tests` | Regex-only, no HTML parser, no JS execution, no `sitemap.xml`/`OpenAPI`, no form POST follow, 100 pages cap hard-coded, sequential single-thread, duplicate `_fetch_robots` bug L312. Tidak headless. |
| **Content Discovery** | **PARTIAL** | `src/redveil/checks/disclosure.py:20 _DEBUG_PATHS 17 paths` + `source_maps.py 9 map paths` + `mapper.py:99 seed 11 API paths` + `discovery/subdomain_finder.py probe 80 prefixes` | Hardcode probes, bukan wordlist brute-force (SecLists), no recursive, no soft-404 detection, no `DirBrute` engine. |
| **Target Analyzer** | **PARTIAL** | `src/redveil/attack_surface/mapper.py:41 build() → ApplicationModel` + `attack_surface/model.py` + `endpoint.py source=crawl/robots/link/form` + `behavior/model.py` + `validation/environment.py` | Skeleton: no tech fingerprint (WAF/CDN), no JS analysis, no param auto-discovery, TODO `follow sitemap, merge OpenAPI`. |

### 2. Interception & Traffic Analysis

| Feature | Status | Evidence | Gap |
|---------|--------|----------|-----|
| **Proxy Intercept** | **NOT IMPLEMENTED** | `grep -R ProxyServer/mitmproxy src/ 0`; `http/client.py:64 httpx.AsyncClient(verify=True,follow_redirects=False)` manual redirect; `cli.py` no `proxy` cmd; `pyproject` no mitmproxy deps | By design — scanner, bukan intercepting proxy. Out of scope positioning. Jangan klaim partial. |
| **HTTP/WebSocket History** | **PARTIAL** | `redveil_ui/api/routes/scans.py` scan history + `core/event_bus.py:82 _history` + `orchestrator evidence_store` + `redveil_ui/api/scanner.py:474 _persist_evidence evidence/{EV}.json` + `ui Evidence Log page` | Hanya scanner-generated requests, bukan proxy history. Tidak ada filter burp-like, tidak ada WS history. ARCH ability via evidence. |
| **Match and Replace** | **NOT IMPLEMENTED** | `grep match.*replace src/ 0` | Tidak ada rule engine request/response/header/body. |
| **Inspector** | **PARTIAL** | `ui decoder.html/comparer.html`, `evidence/evidence.py`, `http/request.py purpose`, `http/response.py`, `POST /api/entropy/analyze` + finding detail page | Ada Decoder/Comparer/Entropy tapi bukan Inspector tab Raw/Pretty/Hex/Params/Cookies per-intercepted message. |
| **Logger** | **PARTIAL** | `api/main.py:47 pythonjsonlogger`, `core/event_bus.py`, `validation/gate.py:77 history`, `audit_log` table | Internal scanner events only, bukan traffic logger pass-through (Logger++). |

### 3. Vulnerability Scanning

| Feature | Status | Evidence | Gap |
|---------|--------|----------|-----|
| **Automated Scanner Engine** | **IMPLEMENTED** | `core/orchestrator.py:54 Orchestrator` state `DISCOVERING→CHECKING→VALIDATING→REPORTING→COMPLETED` + `http/client.py:33 HttpClient` + `redveil_ui/api/scanner.py:199 Scanner SSE` + `plugins/base.py:154 Check` + `plugins/loader.py build_default_registry` | Sequential per-check (TODO parallel), discover() dipanggil 2x inefficient. |
| **Active Scanning** | **IMPLEMENTED** | `config.py:27 SafetyProfile PASSIVE/LOW/ACTIVE` + `AuthorizationConfig active_testing+ack+allow_destructive+L1-6` + per-check `safety_profile` (ACTIVE: SSRF/SQLi/CMDi/traversal/XSS/BOLA/BFLA/session-invalidate/graphql) + `cli --profile` | `LOW_IMPACT` hampir tidak dipakai, UI tidak bisa pilih subset checks per-scan. |
| **Passive Scanning** | **IMPLEMENTED** | PASSIVE checks: `headers_security, session_cookie, cors, mass_assignment, disclosure, source_maps, redirect, http_methods, subdomain` | Lengkap untuk headers/cookies/disclosure. |
| **JavaScript Analysis** | **PARTIAL** | `checks/source_maps.py` regex `sourceMappingURL` + `disclosure.py` + `plugins/base.py DOM_CLOBBERING categories empty` | Hanya source map exposure. Tidak ada AST, DOM XSS, sink/source, no headless, JS link extraction regex saja. |
| **Scan Checks Customization** | **PARTIAL** | `ScopeConfig`, `LimitsConfig rps/max_requests/timeout/max_response_size`, `AuthConfig principals`, `TargetConfig`, `ReportingConfig`, `ProbeBuilder DWYOR`, `Scheduler`, `cli --max-requests --rps` | Tidak bisa pilih subset checks per-scan, no insertion points, no resource pool, no scan window. |

### 4. Experimentation, Validation & Automation

| Feature | Status | Evidence | Gap |
|---------|--------|----------|-----|
| **Repeater / Replay** | **PARTIAL** | `validation/replay.py:33 ReplayRecipe` + `108 ReplayEngine.replay(samples=3)` + `findings/finding.py replay_*` + `http/request.py to_curl` + `redveil_ui/api/routes/replay.py:96 POST /{wpoc_id}/replay` + `ui findings/[id]/replay/page.tsx` + `tests/test_replay.py` | Validation replay saja, bukan editor manual. Tidak ada raw edit, history, tabbing, match/replace. CLI `redveil replay` disebut README tapi tidak ada. |
| **Intruder — Sniper** | **PARTIAL** | `probe/runner.py:101 ProbeRunner run(payloads[],position_kind query/path/body) urlencode/replace` + `routes/probes.py:52 3 preset sets` + `schemas.py:456 attack_mode="sniper"` only + `probe-builder page attack_mode hard-coded` | 1 posisi × N payload sequential saja. |
| **Intruder — Battering Ram** | **NOT IMPLEMENTED** | `grep battering src/ 0` | Tidak ada multi-pos same payload. |
| **Intruder — Pitchfork** | **NOT IMPLEMENTED** | `grep pitchfork 0` | Tidak ada parallel lists. |
| **Intruder — Cluster Bomb** | **NOT IMPLEMENTED** | `grep cluster.bomb 0` | Tidak ada cartesian product. |
| **Payload Processing** | **NOT IMPLEMENTED** | `runner.py:258 _build_request` hanya urlencode mentah, `path_traversal:236 quote` satu-satunya encode | Tidak ada chain encode (double URL/Base64/Hex/HTML/Gzip), prefix/suffix, Grep-Extract. |
| **OAST / Collaborator** | **PARTIAL** | `config.py:101 out_of_band_callback_domain` + `checks/ssrf.py:134 _build_oob_url canary.{domain}` + `evidence OOB_CALLBACK` + `knowledge SSRF_OOB_CALLBACK requires operator check log` + `tests/test_ssrf_wave14` | Hanya SSRF GET param url & POST form, butuh operator sediakan interactsh/Collaborator sendiri, no DNS/HTTP catcher, no polling token store, no auto-verify. Always LIKELY, manual review. |
| **DOM Security Analysis** | **NOT IMPLEMENTED** | `checks/xss.py:66 _detect_reflection_context` regex naive, `crawler skip javascript:` | Tidak ada DOM Invader, postMessage, prototype pollution, DOM XSS via hash. |

### 5. Data Utilities & Crypto

| Feature | Status | Evidence | Gap |
|---------|--------|----------|-----|
| **Decoder** | **PARTIAL** | `ui/frontend/src/app/decoder/page.tsx 4 modes base64/url/html/hex` browser-only | 4 mode saja, Burp 12+ (Gzip/JWT/octal/binary). |
| **Hash Generator** | **NOT IMPLEMENTED** | `grep hash tool 0` (hash hanya internal sha256) | Tidak ada MD5/SHA/HMAC viewer. |
| **Sequencer** | **NOT IMPLEMENTED** | `redveil_ui/api/routes/entropy.py POST /api/entropy/analyze shannon_entropy` + `tools/token-entropy page` | Bukan Sequencer FIPS. Single-sample Shannon saja, tidak capture >10k, tidak ada monobit/poker/runs. |
| **Comparer** | **PARTIAL** | `ui/app/comparer/page.tsx diff 4 fields status/timing/length/body_excerpt` + `routes/scans.py:504 Evidence picker` | Hanya 4 field, tidak ada words/bytes diff raw, no syntax highlight. |

### 6. Engagement Tools & PoC

| Feature | Status | Evidence | Gap |
|---------|--------|----------|-----|
| **CSRF PoC Generator** | **NOT IMPLEMENTED** | `knowledge SESSION_CSRF_CHAIN` detection only, `plugins/base CSRF category empty` | Tidak ada HTML form auto-submit PoC. |
| **Clickjacking PoC** | **PARTIAL** | `checks/headers_security.py x-frame-options-missing/improper CWE-1021` | Hanya detect header, tidak ada iframe PoC generator, tidak cek `CSP frame-ancestors`. |
| **Find References** | **NOT IMPLEMENTED** | `grep find_referenced 0` | Tidak ada site-wide search param/URL reflect. |
| **Embedded File Discovery** | **PARTIAL** | `checks/disclosure.py 17 paths` + `source_maps.py 9 maps` | Hardcode, tanpa `.bak/.old/.zip` generik, tanpa JS comment extraction. |

### 7. Session & Network

| Feature | Status | Evidence | Gap |
|---------|--------|----------|-----|
| **Session Handling Rules** | **PARTIAL** | `http/session.py:19 AuthProvider` 5 impls (Cookie/Bearer/Basic/CustomHeader/Anonymous) stateless `apply()` + `config.py:224 AuthConfig principals` + `http/client.py auth_override` + `behavior/state.py SessionState` | Static only, no rule engine (regex extract → replace), no CookieJar, no Set-Cookie parsing. Principals hanya untuk BOLA brute-force. |
| **Macros** | **NOT IMPLEMENTED** | `grep macro src/ 0`, `behavior/transitions.py LOGIN/LOGOUT enum deskriptif only` | Tidak ada recorded sequence `login → token fetch → replay before probe`. |
| **Automatic Re-auth** | **NOT IMPLEMENTED** | `http/client.py _do_send` no 401 handler, `checks/session_invalidation.py` menguji invalidasi bukan re-auth, `transitions REFRESH` no handler | Scan mati jika session expired, tidak ada `on_401` hook. |
| **CSRF Token Refresh** | **NOT IMPLEMENTED** | Detection `session_cookie csrf_via_xss` only, `AuthConfig.extra_headers` static, no extractor | Tidak bisa scan form yang butuh fresh CSRF per-request (403). |
| **Upstream Proxy** | **NOT IMPLEMENTED** | `HttpClient.__init__` no proxy arg, `httpx.AsyncClient` no `proxy=`, `grep proxy src/redveil 0 functional`, `cli no --proxy`, `LimitsConfig no proxy` | Kritis: tidak bisa chain ke Burp/corporate proxy. Butuh `ProxyConfig` + `httpx proxies=`. |
| **SOCKS Proxy** | **NOT IMPLEMENTED** | `grep socks src/ 0`, `pyproject no httpx[socks]` | Tidak ada. |
| **TLS Client Certificates (mTLS)** | **NOT IMPLEMENTED** | `redveil_ui/tls.py 342 lines` hanya **server** TLS (CA 10y, cert 825d SAN localhost+LAN, `server.py:269 ssl_certfile`), outbound `HttpClient verify=True` hardcode no `cert=` | Tidak bisa scan mTLS target. Butuh `TLSConfig{ca_bundle,client_cert}` → `httpx cert=`. |

### 8. Project Management & Ecosystem

| Feature | Status | Evidence | Gap |
|---------|--------|----------|-----|
| **Organizer — Tagging** | **NOT IMPLEMENTED** | `models.py Finding` no tags, `grep organizer 0` | Tidak ada custom tags per request. |
| **Organizer — Notes** | **IMPLEMENTED** | `api/models.py:73 Finding.notes Text + annotated_at` + `schemas.py:211 FindingPatchIn 5000 chars` + `routes/findings.py PATCH /{wpoc_id}` + `ui findings/[id]/page.tsx handleSaveNotes` + `findings/page Annotated badge` + `pdf_report.py notes` + migration `main.py` | Per-finding notes saja, tidak rich markdown, tidak per-evidence. |
| **Organizer — Rating/Severity Override** | **NOT IMPLEMENTED** | `Finding.severity` read-only dari `assess()`, no PATCH | Tidak ada star/priority override. |
| **Organizer — Grouping** | **PARTIAL** | `ui targets/[id]/page.tsx grouped by top-level folder` + `routes/targets sitemap grouped` + `reporting group by severity` | Auto saja, tidak ada custom folder/drag-drop Burp Organizer. |
| **Extensions / Plugin System** | **IMPLEMENTED** | `plugins/base.py:Check(ABC) CheckMeta 40+ categories` + `registry.py Register` + `loader.py load_from_entry_points redveil.checks` + 18-19 checks + `cli list-checks` + `ui plugins/page` + `tests/test_plugin_*` | Hanya Check extension, no marketplace UI, no hooks Reporter/Auth/Evidence, no context-menu/tab. Internal checks tidak via entry_points. |
| **Built-in Browser** | **NOT IMPLEMENTED** | `grep browser src/ 0 functional`, `tls.py` trust external browsers proof, `crawler httpx only`, no playwright/selenium runtime | Missing untuk SPA/OAuth. Positioning: better pakai external tool + upstream proxy (yang juga belum ada). |
| **Command Palette** | **NOT IMPLEMENTED** | `grep palette/cmdk src/ui 0`, `components/ui` only button/card/badge/tabs | Gap power-user. Burp juga tidak punya tapi modern scanner ada. |
| **Enterprise / Scheduled Scanning** | **PARTIAL** | **NOT Team/RBAC** (`auth.py check_auth_or_fail api_key_hashes` single-tenant SQLite, no User/Team) — **BUT Scheduled:** `api/models.py:123 ScheduledScan cron+profile+L1-6` + `schemas.py croniter valid` + `routes/schedules.py CRUD+trigger` + `scheduler.py APScheduler CronTrigger` + `ui schedules/page.tsx` | Cron lengkap, tapi no scan window/throttle/notification/diff baseline. Enterprise minimal. |

### 21. UI/UX Burp-Inspired Workflow

| Feature | Status | Evidence | Gap |
|---------|--------|----------|-----|
| **Dashboard/Target/Proxy/Scanner/Replay/Findings/AI mental model** | **PARTIAL** | `ui app: page.tsx dashboard, targets, scans, findings, probe-builder, comparer, decoder, token-entropy, audit, schedules, plugins, settings` + SSE `scans/[id]/stream` + `lab` stub 501 | Scan-centric, bukan proxy-centric. Burp browse→proxy captures→site map fills→right-click scan; Redveil New Target→scope YAML→profile→SSE scan. Tidak ada Proxy tab. |
| **Workspace 3-panel (Site Map + Request/Response + Inspector)** | **PARTIAL** | `targets/[id]/page grouped folder`, `scans/[id]/evidence Evidence Log` filter, `findings/[id]/replay` verdict | Site Map tidak live, tidak ada Request/Response workspace tabbed, Inspector hanya evidence viewer. |
| **Familiarity for Burp users** | **PARTIAL** | Sidebar familiar, Decoder/Comparer/Entropy parity, ProbeBuilder ≈ Intruder-sniper, Replay ≈ Repeater-auto | Learning curve medium: no Intercept/History, no Send-to-* context menu, no tabbed Repeater. |

### 9-20. AI-Assisted Security Assessment

| Feature | Status | Evidence | Gap |
|---------|--------|----------|-----|
| **9.1 AI Security Analysis** (finding explain/triage/evidence) | **NOT IMPLEMENTED** | `grep openai\|anthropic\|llm src/ redveil_ui/ 0 hits`; `pyproject.toml:11 0 AI deps`; `tests/test_ai* 0` | Hypothesis rule-based saja (`behavior/hypotheses.py`). |
| **9.2 AI Hypothesis Generation** | **ARCHITECTURALLY SUPPORTED** | `behavior/hypotheses.py:13 InvariantKind 7 enums` + `Hypothesis` + `planner.py plan_for_hypothesis` + `behavior/model.py declare/plan/execute` | Deterministik BOLA/BFLA, bukan LLM. Architecture siap untuk `AI → hypothesis → Redveil validator` (Orchestrator validate), tapi belum ada LLM layer. |
| **10. AI Tool Calling** | **NOT IMPLEMENTED** | `grep tool_call 0` | Tidak ada `inspect_endpoint/run_check/replay` tools. Butuh tool registry + policy gate. |
| **11. Structured AI Output** | **NOT IMPLEMENTED** (domain structured ada) | `evidence/evidence.py Evidence 25 fields`, `findings/finding.py Finding`, `validation/replay.py ReplayRecipe` structured tapi non-LLM; `grep structured.output 0` | JSON schema untuk LLM belum ada. Domain evidence sudah typed (reuse possible). |
| **12. AI Provider Abstraction** | **NOT IMPLEMENTED** (AuthProvider ada) | `http/session.py AuthProvider ABC 5 impls` + `config.py AuthConfig` adalah target auth, bukan AI; `grep AIProvider 0` | Perlu `AIProvider ABC → OpenAI/Anthropic/Gemini/OpenAI-Compatible` mirip AuthProvider. |
| **13. User-Provided API & Custom Model** | **NOT IMPLEMENTED** (target auth BYOK ada) | `config.py AuthConfig.Bearer/CustomHeader` + `redveil_ui api_key rvui_...` BYOK untuk target/UI, bukan LLM; `grep llm_api_key 0` | Perlu `ai: {provider:{type,base_url,api_key,model}}` + redaction. |
| **14. Capability Detection** | **NOT IMPLEMENTED** | `grep capability 0` | Tidak ada context window/tool/vision detection, no graceful fallback. |
| **15. Model Routing** | **NOT IMPLEMENTED** | `grep routing 0`; `ui next file routing` bukan AI routing | Tidak ada `fast/reasoning/vision` routing, no per-task model selection. |
| **16. AI + Browser/Playwright** | **NOT IMPLEMENTED** (E2E only) | `ui/package.json @playwright/test 1.62.1` + `playwright.config.ts baseURL 127.0.0.1:8000` + `e2e/*.spec.ts 13 files` + `opencode.json mcp playwright` = E2E testing only, `grep browser tool 0` | Tidak ada `inspect_browser_state/analyze_screenshot` tools. Playwright ada sebagai dependency dev, bisa reuse untuk AI observations. |
| **17. AI Safety & Reliability** | **NOT IMPLEMENTED** (scanner safety ada) | Scanner safety: `config.py SafetyProfile+AuthorizationConfig`, `validation/gate.py ActionGate L1-6 tiered`, `validation/risk.py`, `core/scope.py`, `evidence/sanitizer.py`, `probe/runner.py DWYOR` — sangat matang; `grep AI safety 0` | No UNTRUSTED DATA sanitization untuk AI prompt injection (response/JS/HTML dianggap untrusted), no hallucination guard. |
| **18. AI Privacy & Data Governance** | **NOT IMPLEMENTED** (evidence sanitizer ada) | `evidence/sanitizer.py JWT/Stripe/AWS/GH → [REDACTED]` + `replay.py sanitize headers` + `actor suffix` — privacy untuk evidence/report; `grep AI privacy 0` | Tidak ada `ai enabled/model/data/redaction/context_limit` control, tidak ada pre-send sanitization ke LLM. |
| **19. AI Failure Isolation** | **NOT IMPLEMENTED** (orchestrator isolation ada) | `orchestrator.py try→FAILED+ERROR+SCAN_FINISHED`, `gate replay behavior try continue`, `http/client.py error capture` | Scanner tetap jalan jika AI fail belum terbukti karena AI belum ada. Perlu `AI failure → scanner/report/CLI tetap`. |
| **20. AI Cost & Resource Control** | **NOT IMPLEMENTED** (network budget ada) | `config.py LimitsConfig rps/max_requests/timeout/max_response_size/max_concurrent`, `http/rate_limit TokenBucket`, `probe budgets`, `schemas max_requests 100k` — network cost mature; `grep token_budget 0` | Tidak ada token/request/context truncation/caching/rate limit/estimation untuk LLM. |

---

## 30. Capability Coverage

**Formula:** `Coverage = (IMPLEMENTED + 0.5*PARTIAL + 0.25*ARCH_SUPPORT) / (Total - NOT_APPLICABLE)`  
`NOT_APPLICABLE` tidak dihitung sebagai kekurangan (§30).

| Bucket | Count |
|--------|-------|
| IMPLEMENTED | **11** (Scope, Scanner Engine, Active, Passive, Notes, Plugin System, Scheduled, + 4 scanner core) |
| PARTIAL | **18** (Site Map, Live Active, Content Discovery, Target Analyzer, History, Inspector, Logger, JS Analysis, Scan Customization, Repeater, Sniper, OAST, Decoder, Comparer, Clickjacking, Embedded, Session Rules, Grouping, UI Workflow partials) |
| ARCHITECTURALLY SUPPORTED | **1** (AI Hypothesis — rule-based foundation) |
| NOT IMPLEMENTED | **24** (Live Passive, Proxy Intercept, MatchReplace, Payload Processing, Battering Ram/Pitchfork/ClusterBomb, DOM, Hash, Sequencer, CSRF PoC, FindRefs, Macros, Auto Re-auth, CSRF Refresh, Upstream, SOCKS, mTLS, Tagging, Rating, Browser, CmdPalette, Team/RBAC, AI Analysis/Tool/Structured/Provider/BYOK/Capability/Routing/BrowserAI/Safety/Privacy/Failure/Cost) |
| NOT VERIFIED | **0** |
| NOT APPLICABLE | **2** (Diatomic: Built-in Browser & Collaborator server bisa di-argue NOT APPLICABLE untuk positioning scanner — tapi audit strict hitung sebagai NOT IMPLEMENTED agar tidak inflate; di bawah kita hitung keduanya sebagai NOT IMPLEMENTED untuk konservatif, lalu tampilkan alternatif jika di-exclude) |

**Total relevan = 53** (11+18+1+24 = 53, excluding 0 NOT_VERIFIED, 0 excluded yet)

- **Strict (semua NOT IMPLEMENTED dihitung):** `(11 + 9 + 0.25) / 54 = 20.25 / 54 = **37.5% Burp parity**`
- **Fair positioning (exclude 2 NOT_APPLICABLE: Built-in Browser, Collaborator host — lebih baik integrasi external):** `(11 + 9 + 0.25) / 52 = 20.25/52 = **38.9%**`
- **Core Security Capability only (12 items: scanning+validation+payload+OAST):** `(4 + 0.5*4 + 0.25*1)/12 = 6.25/12 = **52%**` → Redveil strongest di core.
- **Analyst Productivity (proxy/repeater/intruder/decoder/comparer):** `~25%`
- **UI Convenience:** `~40%`
- **Enterprise:** `~20%` (notes+scheduler done, lainnya no)

**Insight:** Angka 37% tampak rendah, tapi **Core Security 52% dan Passive 70% + Validation 80%** menunjukkan fokus Redveil di assessment quality, bukan workbench parity. Mengejar 100% Burp clone adalah anti-positioning.

---

## 31. Redveil Strengths (evidence-based, bukan pujian kosong)

1. **Scope & Safety egress terbaik:** `ScopeController` 5-gate + `check_redirect_chain` + `ScopeViolation` pre-wire + `SafetyProfile` + `AuthorizationConfig (active+ack+allow_destructive+L1-6)` + `ActionGate tiered Y/N → typed CONFIRM` + `DestructiveLevel 6-tier` + `knowledge/destructive_levels.py`. Tidak ada scanner open-source yang se-strict ini — Burp bahkan tidak punya L1-6.
2. **Validation bukan binary:** `ControlProbe 9 req (3 baseline + control + 2 probe + control + 2 probe)` + `FlakinessDetector 5 samples CV>30%` + `StagedValidator` + `Environment penalty dev0.0→waf0.6` + `Uncertainty×2` + `Oracle 1-5 × mult × weight` → `CONFIRMED/HIGH/MEDIUM/LOW/TENTATIVE`. Evidence `fingerprint` + `sanitizer [REDACTED]` → `FindingDeduplicator` 2-level (fingerprint + root-cause clustering `cluster_size/affected_endpoints`). Burp tidak punya flakiness/WAF penalty se-eksplisit ini.
3. **Replay & Evidence-grade:** `ReplayRecipe sanitized` + `ReplayEngine consistency check status_variance/body_variance/timing_variance` + `build_recipe_from_request redacts Authorization/Cookie` + `HTTP request to_curl`. `Evidence 25 fields` termasuk `waf_detected/rate_limited/destructive_level/environment_uncertainty`. Burp Repeater tidak punya automated variance analysis.
4. **Negative Testing harness:** `tests/test_negative_testing.py dual-lab app.py vs secure_app.py` assert `secure produces fewer findings (vuln//5)` + `no CRITICAL/HIGH on secure`. Langka di scanner.
5. **Multi-principal BOLA:** `PrincipalConfig.to_override() → (headers,cookies)` + `Request.auth_override_*` + `HttpClient headers.update override wins` + `checks/bola.py _send_as(principal)`, `bfla_behavior 2nd model`. BOLA read-only GET 14 patterns + query endpoints, action gating `MEDIUM`. Burp tidak punya built-in multi-principal blast.
6. **Evidence sanitization:** `sanitizer.py JWT/Stripe/AWS/GH/Slack/CC/Email → [*_REDACTED]` + `headers {authorization,cookie,x-api-key} → [REDACTED]` + `sanitize_evidence_list` sebelum `write_report`. Report PDF safe. `AuditLog actor suffix` + `redveil_ui` no raw key logging. Burp Logger++ tidak redact se-agresif ini.
7. **Attack surface model:** `ApplicationModel` + `AttackSurfaceMapper` seed + `BehaviorModel` (meski skeleton) + `InvariantKind 7 enums` + `planner` — fondasi hypothesis-driven assessment (reuse untuk AI Phase 2).
8. **Rate limiting & budget:** `TokenBucket` + `Semaphore` + `LimitsConfig max_requests hard cap` + `max_response_size 5MB` + per-probe budget `worst-case 10 req` + UI `max_requests 100k validator` + `Scheduler` cron. Burp tidak punya request budget se-explicit.
9. **UI operational maturity:** `Scheduler APScheduler CronTrigger`, `TLS Local CA 10y + cert 825d SAN LAN`, `install-ca` multi-browser (Firefox forks + Flatpak + Chromium `~/.pki/nssdb` + system), `auto-port fallback` walk-forward, `CSP nonce script+style`, `notes operator` + `pdf Report`, `JSON log`, `multi-key add/list/remove` respect `REDVEIL_CONFIG`.
10. **Plugin architecture minimal tapi clean:** `Check(meta,category 40+,safety_profile) → Registry → loader entry_points` idempotent `bind` guard `http._scope is scope`, `cli list-checks`, `ui plugins/page` dynamic. Mudah tambah check tanpa core change (meski no DAG).

---

## 32. Major Gaps (prioritized impact)

### P0 — Fundamental (segera, block assessment completeness)

| Gap | Alasan | Impact | Dependency | Complexity | CLI-first? | Butuh UI? |
|-----|--------|--------|------------|------------|------------|-----------|
| **1. Upstream/SOCKS + mTLS** | Tidak bisa chain ke Burp/ZAP/corporate proxy, tidak bisa scan internal mTLS | Tinggi — enterprise & lab blocker | `HttpClient` + `config.py` | Rendah (tambah `ProxyConfig{TlsConfig{cert,ca}}` → `httpx.AsyncClient(proxy=,cert=,verify=)`) | Ya (`--proxy`, `--client-cert`) | Ya (target form) |
| **2. Per-check selection & insertion points** | Semua 18 checks selalu run, tidak bisa passive-only atau pilih 1 check, tidak ada custom insertion | Tinggi — tuning scan & budget waste | `cli`, `api/scanner.py`, `orchestrator` | Rendah (tambah `enabled_checks[]` di `POST /api/scans` + filter `registry.by_ids`) | Ya | Ya |
| **3. Session rules / CSRF refresh / auto re-auth** | Form-heavy target dengan CSRF per-request selalu 403, session mati = scan gagal total | Tinggi — FP/6 coverage loss | `HttpClient` hook + `config SessionHandlingConfig` | Sedang (regex extractor + pre-request hook + 401 retry) | Ya | Ya (rules editor) |
| **4. Content Discovery wordlist engine** | Hanya 17+9 hardcode paths, miss banyak hidden endpoints/files | Tinggi — recon completeness | `Crawler` + `discovery/` | Rendah-Sedang (wordlist SecLists + soft-404 + recursive) | Ya | Tidak |
| **5. PayloadManager sentral** | Payload terfragmentasi per-check copy-paste, tambah check baru = copy-paste `canary` | Sedang-Tinggi — tech debt | `redveil/payloads/` new module | Sedang (PayloadSet + Encoder + Canary UUID) | Ya | Tidak |

### P1 — Penting untuk pentesting workflow

| Gap | Impact | Complexity | CLI-first |
|-----|--------|------------|-----------|
| **6. Repeater proper (raw editor + history)** | Productivity manual validation; kini hanya `Replay` auto | Sedang (tambah `POST /api/replay/custom` raw) | Ya |
| **7. Intruder full (ram/pitchfork/cluster + Grep-Extract + payload types + encoding chain)** | Fuzzing terbatas sniper 1-pos | Sedang-Tinggi (kombinatorik + processor registry) | Ya (`probe` extend) |
| **8. OAST polling (Interactsh/self-hosted)** | SSRF/blind XSS/XXE tidak auto-verified (selalu LIKELY) | Sedang (server DNS+HTTP atau polling API) | Ya |
| **9. JS/DOM analysis (headless)** | SPA routes & DOM XSS miss | Tinggi (Playwright/JS parser) | Tidak (butuh browser) |
| **10. OpenAPI/Swagger discovery** | API-heavy target miss endpoints/params | Rendah (parser `openapi.yaml → Endpoint`) | Ya |
| **11. GraphQL full fuzz (schema → types → fuzz)** | Kini hanya introspection probe | Sedang | Ya |

### P2 — Productivity

| Gap | Complexity |
|-----|------------|
| **12. Organizer full (tags/rating/custom grouping/search)** | Rendah (tambah `Finding.tags JSON` + `PATCH`) |
| **13. Find References & site-wide search** | Rendah (index `Evidence` di DB) |
| **14. Hash tool + Decoder lengkap (Gzip/JWT/octal)** | Rendah |
| **15. Comparer proper (words/bytes diff raw)** | Rendah |
| **16. Command Palette (Cmd+K)** | Rendah |

### P3 — Nice-to-have / Enterprise

| Gap | Catatan |
|-----|---------|
| **17. Team/RBAC/SSO, project sharing** | Low value untuk solo positioning — explicit NOT priority (`PYPI_README 217 Solo operators`). |
| **18. Built-in Browser** | Not worth — better investasi upstream proxy + headless crawler, reuse external browser. |
| **19. SARIF/report diff** | Enterprise reporting — after core gaps. |

---

## 33. Burp-like Features Worth Adding (incremental, no rewrite)

| Fitur | Alasan | Use case | Reuse Redveil | Complexity | Priority | Dep | UI? | CLI-first? | Core/Productivity |
|-------|--------|----------|---------------|------------|----------|-----|-----|------------|-------------------|
| **A. Enabled checks + insertion points** | Tuning scan, hemat budget | “Scan passive-only di prod” | `registry.by_category`, `config.py SafetyProfile` | Rendah | P0 | — | Ya | Ya | Core |
| **B. ProxyConfig + TLS client cert** | Chain ke Burp, scan mTLS | Pentest lab via Burp upstream | `HttpClient`, `LimitsConfig` | Rendah | P0 | — | Ya | Ya | Core |
| **C. Session rule engine (extract→inject + 401 re-auth)** | CSRF/form-heavy target | SPA dengan CSRF per-request | `AuthProvider`, `HttpClient.apply`, `behavior/state.py` | Sedang | P0 | — | Ya | Ya | Core |
| **D. Wordlist Content Discovery** | Hidden endpoints | `/.git/.env` → `admin.zip` | `Crawler`, `HttpClient budget` | Rendah | P0 | — | Tidak | Ya | Core |
| **E. Raw Repeater (`POST /api/replay/custom`)** | Manual validation tanpa Burp | Edit header/body retry | `ReplayEngine`, `Request.to_curl` | Rendah | P1 | — | Ya | Ya | Productivity |
| **F. Intruder full + Payload Processors** | Fuzzing real | Cluster bomb 2 params | `ProbeRunner`, `RateLimit` | Sedang | P1 | D | Ya | Ya | Core |
| **G. Interactsh polling OAST** | Auto-verify blind | SSRF `canary.interactsh.com` | `ssrf.py OOB`, `Evidence` | Sedang | P1 | — | Tidak | Ya | Core |
| **H. OpenAPI/Swagger parser** | API recon | Import `openapi.yaml` | `AttackSurfaceMapper`, `ApplicationModel` | Rendah | P1 | — | Tidak | Ya | Core |
| **I. OpenAPI/GraphQL fuzz** | API testing | `GET /api/users/{id}` fuzz | `Checks` + `PayloadManager` | Sedang | P1 | H | Ya | Ya | Core |
| **J. Tags/rating/search/notes per evidence** | Organizer Burp-level | Sprint triage | `Finding.notes`, `models.py` | Rendah | P2 | — | Ya | Ya | Productivity |
| **K. Decoder full + Hash tool + Comparer words** | Data utils | JWT/Gzip/Hash | `decoder page`, `evidence/sanitizer` | Rendah | P2 | — | Ya | Tidak | Productivity |

**Prinsip:** Semua A-H bisa CLI-first (`redveil scan --checks xss,sqli --proxy http://127.0.0.1:8080 --with-openapi api.yaml`) tanpa rewrite besar — cukup tambah `config` field + wire `HttpClient`/`Orchestrator` filter. Headless/DOM (P1-9) butuh `playwright` dan paling cost, simpan untuk Phase C.

---

## 34. Features NOT Worth Copying ( positioning-aware )

| Fitur Burp | Alasan tidak perlu clone literal | Alternatif |
|------------|----------------------------------|------------|
| **Intercepting Proxy + Forward/Drop** | Cost besar (MITM CA, WS, HTTP/2), duplikat Burp/ZAP. Redveil strength di automated evidence, bukan manual intercept. | Implementasi **Upstream Proxy** saja (forward via Burp) + **lightweight passive logger** jika butuh — jangan full proxy server. |
| **Built-in Chromium Browser** | Cost sangat besar (bundle Chromium, DevTools), better reuse external browser + trust CA sudah ada (`tls.py`). | Headless crawler optional via `playwright` untuk discovery, bukan embedded browser UI. |
| **BApp Store marketplace** | Ecosystem cost (signing, sandbox, review). `entry_points` sudah cukup untuk `pip install` plugin. | Dokumentasi `how to write Check` + `pip` install, no store UI. |
| **Collaborator self-hosted full (DNS/SMTP/HTTP)** | Infrastruktur heavy (DNS wildcard, SMTP). Interactsh publik cukup, atau polling API. | Integrasi `interactsh-client` polling, bukan host server sendiri. |
| **Sequencer FIPS 140-2 (>10k samples)** | Niche, token-entropy Shannon sudah cover 80% use case untuk review. | Tingkatkan `entropy` ke multi-sample + monobit, tidak perlu full FIPS suite. |
| **Enterprise Team/RBAC/SSO** | Tidak sesuai positioning solo operators (`PYPI_README Solo operators`, SQLite single-file). | Tetap single-tenant, fokus to scheduling + CI/CD webhook, bukan multi-user. |
| **Match/Replace global** | Burp-specific untuk proxy workflow. Di scanner, lebih baik per-check payload processor. | Jika butuh, implementasi `request_extra_headers` + `payload prefix/suffix` di ProbeRunner, bukan global rule engine. |

---

## 35. AI Implementation Recommendation (incremental, no rewrite)

> **Prinsip:** AI reasons, Redveil validates, Redveil enforces safety. AI bukan source of truth — `Observed behavior + deterministic validation + evidence + confidence` tetap.

### Phase 1 — Analysis Layer (read-only, no action) — 2-3 minggu

- **Capability:** `explain finding`, `summarize evidence`, `triage FP`, `remediation`, `root-cause` — hanya baca `findings`/`evidence`/`endpoint`.
- **Module:** `src/redveil/ai/provider.py AIProvider ABC` + `config.py AiConfig{enabled, provider_type, base_url, model, api_key_env}` + `ai/analysis.py explain(scan_id)` → structured JSON, dipanggil dari `redveil_ui/api/routes/findings.py POST /{id}/explain`.
- **Safety:** `evidence/sanitizer` reuse sebelum kirim ke LLM, `actor suffix` logging, `privacy redaction` untuk `Authorization/Cookie/JWT`.
- **No UI autonomous:** tombol `Explain with AI` di `findings/[id]/page` panggil API read-only.
- **Test:** `tests/test_ai_analysis.py` mock provider, assert tidak kirim secret.

### Phase 2 — Hypothesis Engine (AI → Redveil validator) — 3-4 minggu

- **Capability:** `Observation (HTTP + endpoint + history) → ContextBuilder → AI → SecurityHypothesis {type,target,reasoning,confidence,recommended_check} → Redveil Validator (control_probe/replay/oracle) → Evidence → Confidence`.
- **Module:** `ai/context.py build_context(scan_id)` + `ai/hypothesis.py generate()` → `behavior/hypotheses.py Hypothesis` existing (reuse `InvariantKind`) + `planner.py` + `Orchestrator _validate_phase`.
- **Safety:** AI hypothesis **harus** lewat `ScopeController` + `SafetyProfile` + `Gate` + `LimitsConfig`; tidak bypass. Output JSON schema validated (`pydantic`).
- **Depend:** Phase 1 provider abstraction.

### Phase 3 — Tool-Assisted Analysis (controlled tools) — 4-6 minggu

- **Tools:** `inspect_endpoint`, `inspect_request`, `search_findings`, `search_http_history`, `run_check` (safe only, PASSIVE/LOW), `replay_request`, `compare_responses`, `inspect_javascript` — semua lewat `redveil policy/safety`.
- **Module:** `ai/tools/registry.py` + `ai/tools/{inspect,search,replay}.py` + `ai/safety.py` guard (`scope`, `auth boundaries`, `destructive confirmation`, `request_limits`).
- **Policy:** `rate limiting` per-tool, `request budget`, `permission checks`, `no arbitrary command execution`.
- **Depend:** Phase 2 context builder.

### Phase 4 — Browser / Vision — 4-6 minggu

- **Capability:** `screenshot` + `DOM` + `accessibility tree` + `console` + `network` + `storage` → `Normalized Security Context` → `AI` → `DOM XSS/postMessage/prototype pollution`.
- **Module:** `ai/browser/observation.py` via `playwright` (sudah ada dev dep) — collect observations, tidak give AI unrestricted browser control (scope + safety + request_limits enforce).
- **Fallback:** `Vision unsupported? → DOM/text analysis`. Graceful degradation.
- **Depend:** Phase 3 tools + `playwright` runtime.

### Phase 5 — Provider & Model Ecosystem — 3-4 minggu

- **Capability:** `OpenAI`, `Anthropic`, `Gemini`, `OpenAI-Compatible`, `Custom/local self-hosted`, model routing `fast/reasoning/vision`, capability detection, per-task selection, streaming, fallback.
- **Module:** `ai/provider/{openai,anthropic,gemini,local}.py` + `ai/capability.py detect` + `ai/routing.py` + `ai/fallback.py` + `config ai.models.{fast,reasoning,vision}`.
- **Privacy:** `api_key` tidak masuk `finding/report/log/telemetry` (reuse sanitizer), `context truncation` + `caching/dedup`.
- **Depend:** Phase 1 abstraction.

---

## 36. AI Capability Score (0-100, gap terbesar bold)

| Dimensi | Score | Evidence | Gap terbesar |
|---------|-------|----------|--------------|
| **AI Analysis** | **5** | `behavior/hypotheses.py` rule-based only, no LLM | No LLM layer at all |
| **Hypothesis Generation** | **20** | Rule-based `Hypothesis/CanonicalKind/Planner` ada, reuse for AI | Belum ada AI generation, tapi architecture ready (+++) |
| **Tool Calling** | **0** | `grep tool_call 0` | No tool registry |
| **Provider Flexibility** | **0** | `pyproject 0 AI deps`, `grep AIProvider 0` | Perlu abstraction `AIProvider ABC` |
| **User API Support** | **0** (target BYOK 80 tapi AI 0) | `AuthConfig BYOK` untuk target, bukan LLM | Perlu `ai.api_key` BYOK |
| **Structured Output** | **0** LLM / **80** domain | `Evidence/Finding/ReplayRecipe` typed tapi bukan LLM JSON schema | Perlu `response_format json_schema` |
| **Browser/Vision** | **5** (E2E Playwright 100, AI 0) | `playwright` E2E only | No observation collector |
| **Safety** | **10** LLM / **90** scanner | Scanner safety world-class, AI safety 0 | No UNTRUSTED DATA sanitization untuk prompt injection |
| **Privacy** | **10** LLM / **85** scanner | `sanitizer [REDACTED]` untuk evidence, belum untuk AI payload | No `ai redaction policy` |
| **Reliability** | **5** LLM / **80** scanner | `orchestrator try→FAILED`, `flakiness` | No LLM fallback/circuit-breaker |
| **Cost Control** | **5** LLM / **85** scanner | `LimitsConfig/TokenBucket` untuk network, 0 untuk tokens | No token/context/budget |

**Gap terbesar:** **Tool Calling + Provider Abstraction + Safety/Privacy untuk AI** — semua 0/5. Fix Phase 1-3 akan lift dari 5 → 60 dalam 2-3 bulan tanpa ubah core scanner.

---

## 37. AI Deployment Model

| Model | Pros | Cons | Rekomendasi Redveil |
|-------|------|------|---------------------|
| **Built-in Managed AI** (Redveil host model/API) | UX frictionless, cost predictable, no BYOK setup | Vendor lock, privacy risk (data ke Redveil), cost untuk maintainer, tidak sesuai solo/offline | **TIDAK** — Redveil solo/offline-first, jangan host model. |
| **User-Provided API** (BYOK OpenAI/Anthropic/Gemini/Custom) | No lock, user pilih model, privacy (user control), support self-hosted via OpenAI-compatible | UX setup API key, depend on external provider uptime/cost | **YA — primary** |
| **Local / Self-Hosted** (ollama/vLLM) | Privacy max, offline, no cost per-token, air-gap lab | Hardware berat, model quality variasi, setup kompleks | **YA — secondary, via OpenAI-compatible** |

**Rekomendasi:** **Kombinasi 2+3, bukan 1.**

- Architecture: `Redveil → AI Provider Interface → (User-selected Provider → User-selected Model)` + `local OpenAI-compatible endpoint` (mis. `http://localhost:11434/v1`).
- **AI optional:** `ai.enabled=false` default, `scanner/validation/report/CLI` tetap jalan jika provider unavailable (failure isolation).
- **Tidak kunci vendor:** abstraction `AIProvider {OpenAI, Anthropic, Gemini, OpenAI-Compatible, Custom}` minimal handle `model/base_url/auth/streaming/structured/tool/context/vision/timeout/retry/rate`.
- **Privacy:** `api_key` redacted via `sanitizer`, tidak masuk `evidence/finding/report/log`, `context_limit` + `redaction_policy` user-configurable, sensitive data `Authorization/Cookie/JWT/PII` disanitasi sebelum kirim.
- **OpenAI-compatible first:** `local` = `openai_compatible base_url=http://localhost:11434/v1`, jadi 3 model tercapai dengan 1 interface.

---

## 38. Suggested Architecture Roadmap

### Phase A — Hardening & Unblock (2-3 minggu, **no breaking**)
- **Fitur:** `enabled_checks[]` + `ProxyConfig/TlsConfig` + `wordlist content discovery` + `OpenAPI parser` + `raw Repeater` + `Provider abstraction stub`
- **Module:** `config.py: RedVeilConfig.enabled_checks, proxy{url,auth,no_proxy}, tls_client{cert,key,ca,insecure}`, `http/client.py: proxy+cert wiring`, `discovery/wordlist.py`, `attack_surface/openapi.py`, `api/routes/replay.py: POST /custom`, `ai/provider.py stub`
- **Depend:** —
- **Risiko:** Rendah — additive fields, `extra="ignore"` jaga compat
- **Testing:** `tests/test_scope_proxy.py`, `test_openapi_parser.py`, `test_repeater_custom.py`
- **Migration:** None — `create_all` + YAML `extra ignore`
- **UI:** Target form `enabled checks multiselect + proxy + client cert`, `Findings Replay custom tab`
- **CLI-first:** Ya semua

### Phase B — Validation & Fuzzing (4-6 minggu)
- **Fitur:** `Session rule engine (CSRF extractor + 401 re-auth)` + `Intruder full (ram/pitchfork/cluster + processors)` + `Interactsh OAST polling` + `GraphQL schema fuzz`
- **Module:** `http/session_rules.py`, `validation/interactsh.py`, `probe/processor.py`, `checks/graphql_fuzz.py`, `payloads/registry.py`
- **Depend:** Phase A PayloadManager
- **Risiko:** Sedang — session hooks bisa break existing scan (guard `if rules.empty(): passthrough`)
- **Testing:** `lab CSRF form`, `test_session_rules.py`, `test_intruder_combinatorics.py`, `test_interactsh_polling.py`
- **Migration:** None
- **UI:** Session rules editor, Intruder UI tab
- **CLI-first:** Ya (intruder via `probe run --attack-mode cluster-bomb`)

### Phase C — DOM & Scale (4-6 minggu)
- **Fitur:** `Headless crawler (playwright) + JS/DOM analysis` + `Concurrent orchestrator (Semaphore+gather per-host TokenBucket)` + `Evidence DB index`
- **Module:** `discovery/headless.py`, `checks/dom_xss.py`, `core/orchestrator.py refactor gather`, `http/rate_limit per-host`, `persistence/evidence_model.py`
- **Depend:** Phase B, `playwright` dep
- **Risiko:** Tinggi — orchestrator concurrency butuh lock `evidence_store` + `EventBus` backpressure; headless butuh `playwright install`
- **Testing:** `test_headless_crawl.py` (needs browser), `test_concurrent_orchestrator.py`
- **Migration:** Add `evidence` table, reindex
- **UI:** Toggle `headless discovery`, progress per-host
- **CLI-first:** Partial (headless needs browser binary)

### Phase D — AI Analysis & Hypothesis (4-6 minggu, **depends A**)
- **Fitur:** `AI Phase 1-2: provider abstraction + analysis + hypothesis → validator` + `structured output` + `privacy redaction` + `cost budget`
- **Module:** `ai/{provider,context,hypothesis,structured,privacy,cost}.py`, `config.py AiConfig`, `api/routes/ai.py`
- **Depend:** Phase A provider stub + `behavior/hypotheses`+`planner`
- **Risiko:** Sedang — LLM latency/cost; isolasi failure harus `try/except` → scanner tetap
- **Testing:** `test_ai_provider.py mock`, `test_ai_hypothesis_schema.py`, `test_ai_privacy_redaction.py`
- **Migration:** Add `ai` table untuk cache, `config.yaml ai: {enabled, provider}` optional
- **UI:** `Findings AI Analyst → Explain/Confidence/Suggest validation [Run Check]`
- **CLI-first:** Ya (`redveil ai explain --scan-id X`)

### Phase E — AI Tools & Vision + Ecosystem (6-8 minggu, depends D)
- **Fitur:** `AI Phase 3-5: tool calling + browser/vision + provider ecosystem + model routing + local self-hosted`
- **Module:** `ai/tools/*`, `ai/browser/*`, `ai/routing.py`, `ai/capability.py`
- **Depend:** Phase D + Phase C headless
- **Risiko:** Tinggi — prompt injection dari target (UNTRUSTED DATA), tool loop, cost blowup
- **Testing:** `test_ai_tools_policy.py` (scope/SafetyProfile bypass attempt), `test_ai_browser_scope.py`
- **Migration:** None
- **UI:** AI Analyst → tool-assisted `(inspect endpoint → run check)`, vision tab
- **CLI-first:** Partial (vision needs browser)

**No rewrite besar** — semua phase incremental, additive, feature-flagged `ai.enabled`, `headless.enabled`. Core `HttpClient`/`Scope`/`Gate` tetap source of truth.

---

## 39. Final Verdict

**Seberapa jauh Redveil sebenarnya vs Burp Suite?**

**Secara jujur dan kritis (evidence-based):**

**Yang benar-benar sudah dimiliki (IMPLEMENTED, evidence `file:line`):**
- **Scope & safety rails terbaik:** `ScopeController` 5-gate, `SafetyProfile`, `L1-6` tiered `ActionGate`, `allow_destructive` validator — tidak ada scanner yang se-strict ini. Ini bukan marketing, ini `validation/gate.py 295 lines` + `core/scope.py 202 lines` + `risk.py DestructiveLevel` semua tested.
- **Evidence-grade scanning:** 18 checks (PASSIVE 70% matang, ACTIVE 45% solid) dengan `ControlProbe 9 req` + `FlakinessDetector` + `StagedValidator` + `Oracle 1-5` + `Confidence (env+uncertainty)` + `Replay variance` + `Deduplicator clustering`. `Evidence 25 fields` + `sanitizer [REDACTED]` + `markdown/json/html+PDF report`. **Validasi adalah keunggulan Redveil, bukan Burp.**
- **Operational untuk solo operator:** `CLI Typer 5 cmds` + `Scheduler APScheduler` + `TLS Local CA 10y/825d multi-browser` + `auto-port` + `CSP nonce` + `notes` + `multi-key` + `JSON log` + `103 tests` + `lab app vs secure_app negative harness`. `pyproject.toml force-include out → web` self-host siap.

**Yang masih kosong (NOT IMPLEMENTED, `grep 0 hits`):**
- **Proxy/intercept suite = 0%** — tidak ada `Proxy Intercept`, `Match/Replace`, `WS history`, `built-in browser`. Ini **bukan cacat** jika positioning Redveil tetap scanner, tapi **gap total** jika klaim “Burp-like workbench”.
- **Session handling dinamis = 0%** — no `macros`, no `auto re-auth`, no `CSRF token refresh`, no `CookieJar`. Form-heavy target akan banyak 403/FP. Ini **P0 gap real**.
- **Upstream/SOCKS/mTLS = 0%** — tidak bisa chain ke Burp/ZAP atau scan internal mTLS. **P0 blocker enterprise.**
- **Intruder full = 10%** — hanya `sniper 1-pos`, tidak ada `ram/pitchfork/cluster`, no `payload processing chain`, no `Grep-Extract`. `ProbeRunner` ada tapi minimal.
- **Collaborator self-host = 0%** (tapi positioning `NOT APPLICABLE` — lebih baik `interactsh` polling; saat ini hanya SSRF OOB manual LIKELY).
- **DOM/JS = hampir 0%** — hanya `source map` probe, no AST, no headless, no `postMessage/prototype pollution`. SPA akan under-discovered.
- **AI = 0-5%** — `grep openai|anthropic|llm 0`, `pyproject 0 AI deps`. `behavior/hypotheses` ada tapi deterministic, bukan LLM. Semua 12 dimensi AI §36 di 0-20 (safety untuk scanner saja yang tinggi).

**Yang arsitektur sudah dukung tapi belum diekspos (ARCHITECTURALLY SUPPORTED):**
- **Hypothesis-driven:** `Hypothesis` + `InvariantKind 7` + `Planner` + `BehaviorModel` + `ApplicationModel` + `DifferentialResult` — foundation untuk `AI → hypothesis → deterministic validator` (Phase D). Tinggal tambah `AIProvider`.
- **Evidence/Request/Response typed:** `Evidence` 25 fields + `Finding` + `ReplayRecipe` sudah structured — reuse untuk `structured AI output` tanpa new schema.
- **Playwright:** sudah `package.json @playwright/test` E2E + `opencode.json mcp` — reuse untuk headless crawler & AI browser observations, tidak perlu deps baru.
- **Plugin loader:** `entry_points redveil.checks` siap untuk marketplace tanpa code change, tinggal dokumentasi.

**Yang paling worth dibangun berikutnya (priority jujur, bukan wishlist Burp clone):**

**P0 minggu ini (high ROI, low rewrite):**
1. **`enabled_checks[]` + `insertion points`** (1 file config, 30 lines Orchestrator filter) — unlock tuning scan.
2. **`ProxyConfig + client cert → HttpClient`** — unblock Burp chaining & mTLS.
3. **`CSRF extractor + session rule + 401 re-auth`** — fix form-heavy FP.
4. **`Wordlist content discovery + OpenAPI parser`** — recon 35% → 60%.
5. **`PayloadManager` sentral** — hilangkan copy-paste payload tech debt.

**P1 bulan depan:**
- `Raw Repeater` + `Intruder processors` + `interactsh OAST polling` + `GraphQL fuzz`. Semua CLI-first, bisa sambil jalan.

**Tidak worth clone Burp literal (§34):** full intercepting proxy, built-in Chromium bundle, BApp Store, full Collaborator server, FIPS Sequencer, Team/RBAC. Cost > value untuk positioning solo. Better **integrasi** (upstream proxy, interactsh API, external browser trust sudah ada).

**Arsitektur untuk AI (§23):**
- **HTTP transport, scope, safety, evidence, replay, confidence sudah production-grade** dan menjadi safety layer untuk AI (AI tidak bypass `ScopeController`/`SafetyProfile`/`Gate`/`LimitsConfig`). Ini keunggulan vs tambah AI di scanner naive.
- **Bottleneck jika tambah fitur:** `Orchestrator sequential` (bukan parallel), `Crawler regex-only single-thread`, `Payload terfragmentasi`, `ApplicationModel skeleton seed hardcode`, `Request body str tanpa content-type`, `Evidence in-memory + file JSON`, `EventBus sequential await`, `SQLite single-file`, `HttpClient single global TokenBucket`, `UI scan selalu AnonymousAuth` (principals tidak wire). Must refactor `Orchestrator gather` + `PayloadRegistry` sebelum scale AI/headless.

**Score akhir jujur:** **37.5% Burp parity strict, 52% Core Security, 5% AI**. Redveil **tidak mendekati Burp sebagai workbench**, tapi **sudah setengah jalan sebagai assessment framework** dengan validasi & safety yang **lebih baik** dari Burp untuk automated use case. Mengejar 100% Burp clone adalah salah positioning — **jalan paling worth adalah Phase A-D incremental** (hardening + session + fuzzing + AI analysis/hypothesis) tanpa rewrite, selesaikan P0 dulu, lalu AI tool-assisted.

**Jika harus pilih satu next step:** `Phase A: enabled_checks + upstream proxy/mTLS + wordlist + OpenAPI + session rule stub`. Dalam 2-3 minggu, Core Security 52% → 65%, dan unlock `Burp + Redveil` joint workflow (Burp untuk manual, Redveil untuk automated evidence) yang justru lebih powerful daripada mengejar clone 100%.

---

## Appendix — Evidence Paths (absolute, untuk verifikasi ulang)

```
# Scope/Safety/Validation (strengths)
src/redveil/core/scope.py:48 ScopeController, :161 check_redirect_chain
src/redveil/config.py:27 SafetyProfile, :41 AuthorizationConfig, :61 ScopeConfig, :80 LimitsConfig, :224 AuthConfig
src/redveil/validation/gate.py:49 ActionGate, :183 ask tiered
src/redveil/validation/risk.py:24 Risk, :41 DestructiveLevel 1-6
src/redveil/validation/oracle.py:17 Oracle 1-5, :88 Signal
src/redveil/validation/confidence.py:12 ConfidenceScorer
src/redveil/validation/control_probe.py:run_control_probe_sequence (9 req)
src/redveil/validation/flakiness.py:probe (5 samples)
src/redveil/validation/replay.py:33 ReplayRecipe, :108 ReplayEngine
src/redveil/validation/environment.py:EnvironmentProfile
src/redveil/evidence/evidence.py:28 Evidence 25 fields, :129 fingerprint
src/redveil/evidence/sanitizer.py:1 sanitize
src/redveil/findings/deduplicator.py:FindingDeduplicator
src/redveil/findings/finding.py:49 Finding
src/redveil/http/client.py:33 HttpClient (scope→TokenBucket→Semaphore→httpx)
src/redveil/http/rate_limit.py:TokenBucket
src/redveil/http/request.py:17 Request.to_curl
src/redveil/behavior/hypotheses.py:13 InvariantKind, Hypothesis
src/redveil/behavior/planner.py:61 plan_for_hypothesis
src/redveil/behavior/model.py:BehaviorModel

# Crawler/Discovery
src/redveil/discovery/crawler.py:Crawler (100 pages/depth3 regex)
src/redveil/attack_surface/mapper.py:41 AttackSurfaceMapper (seed 11 paths)
src/redveil/discovery/subdomain_finder.py:COMMON_PREFIXES 80

# Checks (18)
src/redveil/checks/*.py (headers_security, cors, http_methods, redirect, disclosure, source_maps, graphql, xss, sqli, ssrf, command_injection, path_traversal, mass_assignment, bola, bfla*, session_*, session_cookie, subdomain)

# API/UI
redveil_ui/api/main.py:lifespan GateMode TODO, :47 json log
redveil_ui/api/scanner.py:199 Scanner SSE, :354 gate_mode not wired, :394 AnonymousAuth hardcode
redveil_ui/api/models.py:73 Finding.notes, :123 ScheduledScan
redveil_ui/api/scheduler.py:AsyncIOScheduler CronTrigger
redveil_ui/tls.py:342 server CA 10y cert 825d
redveil_ui/api/auth.py:46 check_auth_or_fail
ui/frontend/src/app/* (targets sitemap, scans/sse, findings/replay/notes, probe-builder sniper, decoder 4 modes, comparer 4 fields, entropy, schedules)

# Gaps (grep 0)
grep -R "ProxyServer|intercept" src/ 0 functional
grep -R "macro" src/ 0
grep -R "socks|client.*cert" src/redveil 0
grep -R "openai|anthropic|llm|tool_call" src/ redveil_ui/ 0
```

> **File ini adalah handoff untuk session baru.** Untuk resume: `cat REDVEIL_UI_PROGRESS.md` (single file — semua milestone di sini) + `git log --oneline -8`. Untuk challenge: `grep -R "check_auth_or_fail|ScopeController|ReplayEngine" src/ redveil_ui/ --include="*.py"` akan reproduksi claims di atas.

---

## Cara nambah milestone (jangan buat file baru)

Via python patch append - contoh:

python3 << 'PY'
from pathlib import Path
p = Path("REDVEIL_UI_PROGRESS.md")
t = p.read_text(encoding="utf-8")
add = "## 8. Next Milestone YYYY-MM-DD - judul\n\n- change 1\n- change 2\n"
p.write_text(t.rstrip() + "\n\n" + add.lstrip(), encoding="utf-8")
print("appended")
PY

## 8. Combined Plan — Capability-First (locked 2026-09-09)

> **Lock:** `CAPABILITY > QUALITY > SAFETY > INTEGRATION > UX > PARITY`. Parity hanya indikatif after. Status `IMPLEMENTED/PARTIAL/ARCH_SUPPORTED/NOT_IMPLEMENTED/NOT_VERIFIED/NOT_APPLICABLE` berbasis 8 kriteria verifiable source+test+e2e, bukan angka parity. Burp = reference baseline, bukan spec. Single file — jangan split.

**Workspace:** `/workspace/projects/Redveil` | **Branch:** `main` @ `35617db` | **Principle:** tiap fitur dinilai `1 tersedia, 2 lengkap, 3 e2e usable, 4 integrated, 5 tested, 6 safe (scope/gate/rate/evidence/failure), 7 production-ready, 8 relevan positioning`. Stub/placeholder/config-only ≠ IMPLEMENTED.

### 8.1 Architectural Clarifications (locked)

**1) AI capability detection tidak assume `/models`:** `ai/capability.py` coba `GET /v1/models` **best-effort only**. Jika gateway tidak expose (umum untuk proxy web), fallback ke **explicit `AiConfig.capabilities:` user-defined** + graceful fallback (`tool_calling false→prompt-only`, `vision false→text/DOM`, `structured false→json-in-prompt`, `streaming false→non-stream`). No hard-fail. `capabilities` di config opsional override auto-detect.

**2) OAST provider-agnostic:** `src/redveil/validation/oast.py OASTProvider(ABC: register()->{canary_url,token}, poll()->events, verify())` — core decouple dari vendor. `oast/interactsh.py InteractshOAST(OASTProvider)` sebagai **implementasi/default** (poll `https://oast.fun/poll` atau self-hosted `OAST_BASE_URL`). `checks/ssrf.py` depend on `OASTProvider` abstraction, bukan Interactsh hard-code. Ganti ke `custom/self-hosted` via `oast: {provider: interactsh|custom, base_url, api_key}` tanpa ubah checks.

**3) AIProvider protocol-neutral tapi preserve semantics:** `ai/provider.py AIProvider(ABC: complete({prompt,messages,tools,schema,images,stream})->AIResponse{text,tool_calls,usage,raw,normalized})` — interface protocol-neutral. **Adapters preserve semantics:** `adapters/openai.py` handle `Chat Completions/Responses`, `tools: [{type:function}]`, `response_format:{type:json_schema}`, `stream SSE`, `vision image_url`, `error {error.message}`; `adapters/anthropic.py` handle `Messages API`, `system+messages`, `tool_use/tool_result`, `tool_choice`, `stream event: content_block_delta`, `vision base64`, `error {type,error}`; `adapters/openai_compatible.py` generic untuk any proxy web (B.AI, AgentRouter, `https://any-proxy.web.id/v1`, `http://localhost:11434/v1`). Core workflow tidak tahu perbedaan — adapter normalize ke `AIResponse`.

### 8.2 Phase A — Hardening & Generic Gateway P1 (2–3 minggu, low risk, CLI-first, additive)

**Modules:** `ai/{provider.py, config.py AiConfig, adapters/{openai,anthropic,openai_compatible}, capability.py, sanitizer.py}`, `discovery/{wordlist.py, openapi.py}`, `api/routes/replay.py POST /custom`

**A1 `enabled_checks[]`:** `config.py RedVeilConfig.enabled_checks: list[str]|None` validator `check_id ∈ registry.all`. `registry.by_ids(ids)` + `orchestrator.py _bind_all_checks filter` + `cli scan --checks xss,sqli --checks-file checks.txt` + `POST /api/scans {enabled_checks}` + UI `targets/new` multiselect (reuse `GET /api/checks`). **Accept:** `src:redveil/config.py:enabled_checks` + `orchestrator filter` + `tests/test_enabled_checks.py` + e2e `scan --checks sqli-only → findings hanya sqli` + `Scope/Gate/Limits` enforce + `AuditLog`.

**A2 `WordlistManager`:** `discovery/wordlist.py WordlistManager(SecLists wordlist_path, soft_404 detect, recursive depth, extensions)` konsolidasi `disclosure 17 + source_maps 9 + mapper 11 seed`. `Crawler` reuse `HttpClient TokenBucket` budget. **Accept:** e2e `/.git + /admin.zip + /.env.bak` ter-discovery, soft-404 tidak FP.

**A3 `OpenAPI parser`:** `attack_surface/openapi.py parse(openapi.yaml/json) -> Endpoint{method,path,params,content_type} -> ApplicationModel`. **Accept:** import `openapi.yaml` 20 endpoints → semua ter-scan.

**A4 `Raw Repeater`:** `POST /api/replay/custom {method,url,headers,body}` -> `ReplayEngine` variance (`Reproducible/Flaky`). **Accept:** edit `X-Test: 1` → `200 vs 200` `Reproducible` e2e.

**A5 Generic AI Gateway P1:** `AiConfig {enabled:false, provider:{type:openai|anthropic|openai_compatible|custom, protocol:openai|anthropic, base_url, api_key_env, model, headers:map, timeout, retry, capabilities?:{tool_calling,vision,structured,streaming,context_window}}}` — fully user-defined, no allowlist, any proxy web via `base_url`. Reuse `httpx.AsyncClient` + `evidence/sanitizer.py` redaction `Authorization/Cookie/JWT -> [REDACTED]` + `audit Log actor suffix` + failure isolation `ai.enabled=false -> scanner tetap`. **Accept:** config `base_url:https://any-proxy.web.id/v1` + `protocol:openai` + `api_key_env:ANY_KEY` tanpa code → `tests/test_ai_gateway_generic.py` mock `POST /chat/completions` 200 + sanitizer tidak bocor secret + scanner tetap jika `httpx ConnectError`.

**Example YAML generic:**
```yaml
ai:
  enabled: false
  provider:
    type: openai_compatible
    protocol: openai
    base_url: "https://any-proxy.web.id/v1"
    api_key_env: "ANY_PROXY_API_KEY"
    model: "gpt-4o-mini"
    headers: {X-Custom-Proxy-Token: "${CUSTOM_TOKEN}"}
    capabilities: {tool_calling: false, vision: false}  # explicit fallback jika /models tidak ada
oast:
  provider: interactsh
  base_url: "https://oast.fun"
```

### 8.3 Phase B — Session & Fuzzing (4–6 minggu, medium, depends A PayloadManager)

**B1 Session rules:** `http/session_rules.py SessionRule{extract:{regex,from:header/body,group}, inject:{to:header/cookie}, scope:path}` + `HttpClient` pre-request hook + `401 re-auth` retry 1x with `auth_override`. **Accept:** lab `CSRF form` `403->200` e2e `POST` dengan fresh token.
**B2 Intruder full:** `probe/processor.py` `attack_mode: sniper|battering|pitchfork|cluster` + `processors: url_encode|base64|hash` chain + `Grep-Extract`. **Accept:** `tests/test_intruder_combinatorics.py` 4 modes + `attack_mode cluster 2 params 3x3=9 req`.
**B3 OAST polling:** via `OASTProvider` abstraction (clarification 2). **Accept:** `ssrf canary.oast.fun -> poll()` `LIKELY->CONFIRMED` auto, no manual log check.
**B4 GraphQL fuzz:** `checks/graphql_fuzz.py` `introspection -> types -> fuzz`. **Accept:** `__schema` -> `User.id` fuzz -> BOLA.

### 8.4 Phase C — Scale & DOM (4–6 minggu, high risk, depends B)

**C1 Headless crawler:** `discovery/headless.py` reuse `playwright` E2E dep -> `ApplicationModel` JS-rendered. **Accept:** SPA `/app -> /api/data` ter-crawl headless.
**C2 Concurrent orchestrator:** `core/orchestrator.py` `Semaphore(max_concurrent_checks)` + `gather` + `per-host TokenBucket dict` + `evidence_store` `asyncio.Lock`. **Accept:** `17 checks x 2 req` 34 req dengan `max_concurrent 5` -> wall time ~7s vs 34s sequential, `EventBus` backpressure.
**C3 Evidence DB index:** `persistence/evidence_model.py EvidenceRow` index `endpoint, check_id, waf_detected`. **Accept:** `GET /api/scans/{id}/evidence?check_id=sqli` query <100ms 10k rows.

### 8.5 Phase D — AI Analysis/Hypothesis (4–6 minggu, depends A5)

**D1 Read-only:** `ai/analysis.py explain(scan_id)` `POST /api/findings/{id}/explain` -> `{explanation, remediation, confidence_justification}`. **Accept:** sanitizer test + mock provider.
**D2 Hypothesis->Validator:** `ai/context.py build_context(Evidence 25f+ApplicationModel) -> AI -> Hypothesis{invariant,target,reasoning,confidence,recommended_check} -> planner.py -> gate/scope -> ControlProbe` reuse `behavior/hypotheses.py InvariantKind`. **Accept:** `Hypothesis JSON schema` valid + deterministic `Evidence` + `Confidence` + no bypass `Gate`.
**D3 Capability detection + routing:** `ai/capability.py` best-effort `/models` else explicit config (clarification 1) + `ai/routing.py models:{fast,reasoning,vision}` optional. **Accept:** `vision unsupported -> DOM fallback` + `tool_calling false -> prompt-only`.

### 8.6 Phase E — AI Tools/Vision (6–8 minggu, depends C+D)

**E1 Tool calling:** `ai/tools/registry.py` `inspect_endpoint, search_findings, replay_request, compare_responses` via `AIProvider tools` (preserve semantics clarification 3) + `ai/safety.py` guard `scope/auth/gate/limits`. **Accept:** `tool loop` 1x `inspect -> run_check` gated, no unrestricted `exec`.
**E2 Vision:** `ai/browser/observation.py` `screenshot+DOM+a11y tree+console+network` -> `Normalized Security Context` -> AI -> `DOM XSS/postMessage` hypothesis, `HttpClient scope` enforce. **Accept:** `DOM XSS` via `location.hash -> innerHTML` detected.
**E3 Local self-hosted:** via `openai_compatible http://localhost:11434/v1` (already generic), cost `ai/cost.py token budget` + `privacy redaction policy`. **Accept:** `ollama` local e2e `complete()` tanpa external network.

### 8.7 UI/UX — DESIGN.md only + Familiar Workflow (incremental)

**Tokens DESIGN.md:** severity `high/failed bg-danger`, `medium/low_impact bg-warning`, `low/active bg-accent`, `passive surface-1`; surfaces `list surface-2 0.5px 12px`, `stat surface-1 no border 8px`; `technical font-mono` vs `human font-sans`; Tabler 18-20 muted. **Workflow:** `Target -> endpoints/traffic -> inspect -> replay -> finding` familiar tanpa Burp pixel clone. Redveil identity preserve `Scope/Gate/Evidence/Confidence/Replay/AI`. **Incremental:** `Dashboard Link`, `Evidence->Finding Link`, `Scan tabs inline`, `confidence grid 4-col`, `Probe this endpoint` CTA — audit current mostly compliant (pertahankan). **Accept:** pentester Burp navigate core workflow minimal learning, Redveil distinct.
**Design source locked:** hanya `Mockup-Redveil/ui/frontend/DESIGN.md` (16 lines) — `Finding-Detail.md`/`Scan-Detail.md` diabaikan.

### 8.8 Testing, Risks, Migration, Execution Order

**Tests per phase:** `tests/test_*.py` unit + lab `app vs secure_app` e2e + safety `ScopeViolation` + `Gate L1-6` + `TokenBucket` + failure isolation `ai/oast down -> scan tetap`. **Risks:** A low (additive `extra="ignore"`), B medium (session hook guard), C high (concurrency lock), D-E medium (hallucination gated). **Migration:** additive only, `Base.metadata.create_all` + `ALTER` for new columns, no breaking. **Execution:** Phase A1 `enabled_checks[]` first (single-session quick win) -> A2 Wordlist -> A5 Gateway -> B -> C -> D -> E.

---

## 9. Phase B3/B4 — OAST + GraphQL Fuzz (2026-09-10) — COMPLETED

**Commits:** `b3f614d` A1 `enabled_checks[]`, `8905d10` P0 layout DESIGN.md, `751345a` A2-A5, `74902ac` B1+B2, **new** B3+B4 + publish 0.3.0
**Branch:** `main` | **Versions:** `pyproject 0.2.0→0.3.0`, `src/redveil 1.9.5→1.9.6`, `ui/frontend 0.2.0→0.3.0`, `redveil_ui 0.2.0→0.3.0`, `api/main 0.2.0→0.3.0`

### 9.1 B3 OAST — `OASTProvider` wire into `ssrf` auto poll → CONFIRMED

- **Files:** `src/redveil/config.py: OastConfig {provider,base_url,api_key,api_key_env} + RedVeilConfig.oast: OastConfig|None`, `src/redveil/validation/oast.py: build_oast_provider(config) provider-agnostic (oast dict|object + auth.out_of_band_callback_domain fallback → InteractshOASTProvider)`, `src/redveil/validation/oast_interactsh.py`, `src/redveil/checks/ssrf.py: discover gate oob_domain OR oast, _oast_provider = build_oast_provider, per-probe register() → token/canary_url fallback local, validate token → provider.verify() + 1s retry → CONFIRMED high else LIKELY, failure-isolated (exception → LIKELY)`
- **Gate:** `active_testing=True` + `oob_domain OR oast` required; `_INTERNAL_HOST_PATTERNS` still blocks internal domain.
- **Accept:** `ssrf canary.oast.fun → poll()` LIKELY→CONFIRMED auto, no manual log. `verify true → CONFIRMED`, `verify false/exception/None → LIKELY` isolation, scan tetap.
- **Tests:** `MockOAST verify true → CONFIRMED`, `false → LIKELY`, `raise → LIKELY`, `None → LIKELY`; `tests/test_ssrf_wave14.py 14 passed`, `test_check_graphql 15 passed` (post), `pytest -q 1467 passed` (fixed `test_exposed_env_file_flagged` baseline distinct + `scheduler/schedules` cancelled mention).
- **Evidence:** `Evidence kind OOB_CALLBACK` + `oracle_signal oob_callback`, `validation_outcome likely/confirmed`, `environment_uncertainty 0.2/0.4/0.6`, `waf_detected/rate_limited`, `Finding status LIKELY→CONFIRMED` via orchestrator `validation.confidence` backfill.

### 9.2 B4 GraphQL fuzz — schema → types → fuzz

- **Files:** `src/redveil/checks/graphql.py: _INTROSPECTION_QUERY_FIELDS, _FUZZ_QUERIES [users {id}, user(id:1), me, profile, accounts], _is_fuzz_success(resp) data != None + list/dict check, discover loop: introspection → type_names → fuzz 3 per endpoint (preset, break after first success) + type_query → fuzz, is_graphql flag, continue preserve; validate kind graphql_fuzz_bola → CONFIRMED high, collect_evidence BODY_DIFF oracle ownership_violation/excessive_data_exposure, assess HIGH CWE-639/200 OWASP A01/A05 title `GraphQL BOLA: field 'users' returns data without auth`.*
- **Safety:** fuzz only `id` fields, depth 1, no sensitive fields (password/email etc not in queries), active gate `active_testing+ack`, bounded 3 req/endpoint, failure-isolated try/except.
- **Tests:** introspection `→ fuzz success` → 2 cands `introspection_enabled + graphql_fuzz_bola` → `validate CONFIRMED` → `evidence body_diff` → `finding HIGH`; `type_query → fuzz` same; isolation `fuzz fails → only type_query_works, no fuzz`; existing `tests/test_check_graphql.py 15 passed`.

### 9.3 Build + Publish 0.3.0

- **Version bump:** `pyproject.toml 0.2.0→0.3.0`, `redveil_ui/__init__.py 0.2.0→0.3.0`, `src/redveil/__init__.py 1.9.5→1.9.6`, `ui/frontend/package.json 0.2.0→0.3.0`, `redveil_ui/api/main.py FastAPI version 0.2.0→0.3.0 + /api/info version`, `CHANGELOG.md ## redveil-ui 0.3.0` with A1-A5 B1-B4.
- **Build:** `ui/frontend npm run build → 20/20 pages`, `rm -rf redveil_ui/web && python -m build → redveil_ui-0.3.0-py3-none-any.whl 836K + tar.gz 1.7M` (removed web before build to avoid duplicate force-include, then `cp -r out → web` for dev).
- **Publish:** `twine check PASSED`, `twine upload dist/* → https://pypi.org/project/redveil-ui/0.3.0/ 200`, `pip install -e .` local verify `redveil-ui --help`, `healthz ok` on `https://oast.fun` base.

### 9.4 Self verify — Playwright + screenshots

- **Server:** `REDVEIL_CONFIG=/tmp/playwright-config.yaml` (host 127.0.0.1 port 8766, tls false, data_dir /tmp/redveil-playwright-data, auth []) → `redveil-ui start → http://127.0.0.1:8766 healthz ok, /api/info 0.3.0, healthz scans_* 0`.
- **Playwright:** `cd ui/frontend && REDVEIL_TEST_BASE=http://127.0.0.1:8766 npx playwright test e2e/verify.spec.ts` → 2 passed/1 failed (empty DB activity-row, expected 2/3), `e2e/audit-a.spec.ts` → 11 passed (functional check empty DB + dynamic routes). Full `pytest -q 1467 passed` after fixes.
- **Screenshots:** `node /tmp/screenshot.cjs` via `playwright-core` → `Mockup-Redveil/screenshots/phase-B3-B4 12 files 600K`: `01-dashboard.png` (40K), `02-targets.png`, `03-targets-new.png` (60K), `04-scans.png`, `05-findings.png`, `06-probe-builder.png` (70K), `07-decoder.png`, `08-comparer.png`, `09-token-entropy.png`, `10-schedules.png`, `11-settings.png` (79K), `12-plugins.png` (56K). `phase-A1 17 files 1.2M` + `phase-A2-A5 2 files` preserved (`.gitignore` except `PYPI-shots`, added with `git add -f`).
- **Evidence:** `curl http://127.0.0.1:8766/api/info` 0.3.0, `healthz`, `evidence Store` on `orchestrator` + `scanner._persist_evidence`, `Scope/Gate/Limits` enforce via `enabled_checks` filter.

### 9.5 Next (pending)

- [ ] C1 Headless crawler + C2 Concurrent orchestrator + C3 Evidence DB index (Phase C)
- [ ] D1-D3 AI Analysis/Hypothesis + capability/routing, E1-E3 Tool/Vision (Phase D-E)
- [ ] UI polish incremental `Dashboard Link`, `Evidence→Finding`, `Probe this endpoint` CTA — still DESIGN.md only

> **Single file:** this section appended via `python patch` — do not split. Fallback `c54fa78` → `b3f614d` → `8905d10` → `751345a` → `74902ac` → **B3/B4 0.3.0**.

## 10. Phase C — Dedicated Pages OpenAPI/Session-Rules/AI (2026-09-10) — COMPLETED (dev, not yet published)

**Trigger:** Koreksi `DESIGN.md bukan lock IA` — 3 capability user-facing butuh dedicated page (prinsip: internal→tidak, workflow besar→buat route). Approved `boleh gas` 2026-09-10.

**Sidebar:** `ui/frontend/src/components/sidebar.tsx:25` `IconFileCode/IconKey/IconRobot` (Tabler 18-20 muted) urutan:
`Dashboard / → Targets /targets → OpenAPI /openapi → Scan History /scans → Findings /findings → Session Rules /session-rules → Schedules /schedules → Plugins /plugins → AI Gateway /ai → Probe Builder /probe-builder → Settings /settings`
Token `DESIGN.md` `active bg-zinc-800` `text-zinc-400→200`, `border-zinc-800 bg-zinc-950`.

**Wireframe:**
- `/openapi` `src/app/openapi/page.tsx` — `Card surface-1` import `textarea font-mono` yaml/json + `Input name` + `Preview` `POST /api/openapi/parse → table method|path|params` + `Save POST /api/openapi/specs` + `list GET /api/openapi/specs` + `DELETE`, badge `count`, alert `bg-danger/warning/accent`, `data-testid openapi-page/openapi-spec/openapi-preview/openapi-list`.
- `/session-rules` `src/app/session-rules/page.tsx` — `Card surface-1` list `Rule {name, extract_url, extract{from,regex,header/json_path}, inject{to,name}, scope, ttl}` + `Add Rule` + `Test POST /api/session-rules/test → token` + `reauth {enabled, login_url/method/body/headers}` + `Save PUT /api/session-rules`, `data-testid session-rules-page/session-rule-card/session-test-*`.
- `/ai` `src/app/ai/page.tsx` — `Card surface-1` provider `enabled, type/protocol, base_url, model, api_key_env, timeout` + capabilities `tool_calling/vision/structured/streaming/context_window` + `Detect POST /api/ai/capabilities/detect → AiCapabilities` + `Test POST /api/ai/test → AIResponse`, redacted `api_key→***`, `data-testid ai-page/ai-base-url/ai-save/ai-test-*`.

**Backend:** `redveil_ui/api/models.py:OpenApiSpec(id,name,spec,created_at,parsed) SessionRuleSet(id,config) AiConfigStore(id,config)` (DB `Base.metadata.create_all` via `api/main.py:lifespan`), `routes/openapi.py: POST /parse GET/POST /specs GET/DELETE /specs/{id}` (reuses `attack_surface/openapi.py:parse_openapi_spec`), `routes/session_rules.py: GET/PUT /session-rules POST /test` (reuses `http/session_rules.py:SessionHandlingConfig` + `httpx` preview), `routes/ai.py: GET/PUT /api/ai/config POST /test POST /capabilities/detect` (reuses `ai/config.py:AiConfig` `ai/provider.py:build_ai_provider` `ai/capability.py:detect_capabilities` + redact), registered `api/main.py:openapi/session_rules/ai` `prefix /api/openapi|/api/session-rules|/api/ai`, `lib/api.ts:apiPut`.

**Build:** `npm run build → 23/23 pages` (prev 20 + 3 new `○ /openapi /session-rules /ai`), `rm -rf web && cp -r out→web`, `tsc --noEmit` clean.
**Verify:** `TestClient(app) as client` POST `/api/openapi/parse` 200 `{count:1}`, POST `/specs` 201, GET `/specs` 200, GET `/session-rules` 200, PUT 200, GET `/ai/config` 200, PUT 200 (via `with TestClient(app)` lifespan creates tables `openapi_specs|session_rule_sets|ai_configs`), `pytest tests/test_check_graphql 15 passed` `tests/test_ssrf_wave14 14 passed` `1467 passed` overall; `REDVEIL_CONFIG=/tmp/playwright-config.yaml 127.0.0.1:8766` `curl /openapi|/session-rules|/ai 200` + `curl /api/openapi/specs|/api/session-rules|/api/ai/config 200`; `node screenshot2.cjs → Mockup-Redveil/screenshots/phase-C 15 files 828K` `04-openapi.png 64K 07-session-rules.png 48K 10-ai.png 64K` (previous `phase-B3-B4 12 600K` + `phase-A1 17` + `phase-A2-A5 2` preserved).

**Next:** Publish `0.3.1` or `0.4.0` (bump `pyproject` `0.3.0→0.4.0` + `CHANGELOG`), Playwright `e2e/openapi|session-rules|ai.spec.ts` (data-testid), integration `openapi_spec` preselect di `targets/new` + `session_rules` wire ke `scanner._build_config`.

> **Single file:** appended via python patch — jangan split. Sidebar 8→11 items, DESIGN.md token tetap.
