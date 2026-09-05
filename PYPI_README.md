# redveil-ui

**Self-hosted dashboard for [redveil](https://pypi.org/project/redveil/) scans. Burp-style workspace, real findings, zero cloud dependency.**

[![PyPI version](https://img.shields.io/pypi/v/redveil-ui.svg)](https://pypi.org/project/redveil-ui/)
[![Python](https://img.shields.io/pypi/pyversions/redveil-ui.svg)](https://pypi.org/project/redveil-ui/#files)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/FitzyPrjkt/Redveil/blob/main/LICENSE)
[![Tests](https://img.shields.io/badge/tests-1101%20passing-brightgreen.svg)](https://github.com/FitzyPrjkt/Redveil)
[![redveil](https://img.shields.io/badge/depends%20on-redveil%201.9.6+-blue.svg)](https://pypi.org/project/redveil/)

```bash
pipx install redveil-ui
redveil-ui init
redveil-ui start
# open http://127.0.0.1:8000
```

> ## ⚠️ Before you start — this runs on YOUR network
>
> **redveil-ui is 100% local.** No data leaves the host it runs on. The
> app is bound to `127.0.0.1` by default — it is **not** reachable from
> other devices on your network unless you change the config. If you do
> expose it, every scan it launches is sent from **your** IP address
> against the target you specify. If the target isn't yours, or you
> don't have explicit written permission to test it, the legal and
> ethical responsibility is yours — not the maintainers'.
>
> Because the dashboard is self-hosted, the security perimeter is also
> yours: who can reach the instance, what targets you queue, and
> whether destructive checks are enabled. Treat it like any other
> local service with a security boundary.
>
> The **Probe Builder**'s "Custom payload" mode has a two-gate
> confirmation (Gate 1 + Gate 2, both required). That's not UI friction
> for its own sake — it's because custom payloads sit **outside** the
> curated set of redveil's built-in checks, so the framework can't
> pre-validate them for safety. The two gates exist so you have to
> pause and confirm what you're about to send.
>
> See [`DWYOR.md`](https://github.com/FitzyPrjkt/Redveil/blob/main/DWYOR.md)
> for the full statement.

---

## what you get

The package bundles a FastAPI backend, a Next.js 16 SPA, and the
[`redveil`](https://pypi.org/project/redveil/) library under one uvicorn
process on one port. One install, one config file, one URL to remember.

The screenshots below are taken against this exact package, served by
`redveil-ui start`, with a seeded scan + finding to make the data
realistic. Click any of them to view full-size.

### 1. Targets — register a host before you scan it

![Targets list](https://raw.githubusercontent.com/FitzyPrjkt/Redveil-UI/main/Mockup-Redveil/PYPI-shots/02-targets-list.png)

The starting point. Every scan targets a row in this list. Each row
carries the URL, an optional human label, and the YAML scope block
that the orchestrator hands to the `redveil` library's
`ScopeController`. Add a target once, scan it many times against
different profiles.

The `New target` button (top right) takes you to the combined
**target + scan** form — see "New Scan" below.

### 2. New Scan — target + scan config in one form

![New Scan form](https://raw.githubusercontent.com/FitzyPrjkt/Redveil-UI/main/Mockup-Redveil/PYPI-shots/03-new-target.png)

This is the primary action of the dashboard: register a target
**and** configure the scan in a single form. Fields:

- **URL** (required) — validated client-side for http(s) scheme, blocked from cloud-metadata endpoints (`169.254.169.254` and `metadata.google.internal`).
- **Name** (optional) — operator-friendly label.
- **Scope YAML** (optional) — if omitted, the auto-allow scope from `scope_check.py` lets the target's host through; otherwise a strict `allowed_hosts` / `allowed_paths` block is enforced at scan creation.
- **Profile** — `passive` (default, read-only recon), `low_impact` (non-destructive probes), `active` (exploitation-grade; needs `allow_destructive`).
- **Destructive level ceiling** — `L1` through `L6`. The framework refuses any scan where `level >= L3` and `allow_destructive` is `false`.
- **Allow destructive** — opt-in unlock. Default `false`. Without it, even L3+ checks are denied per-action at runtime.
- **Gate mode** — `non_interactive` (default, auto-approve and log), `strict` (auto-deny MEDIUM+), `interactive` (v2, currently disabled).
- **Max requests** (optional) — hard cap. The form warns if you pick `active` with a budget below `1500` (Time-Based SQLi worst case `640` + Command Injection worst case `1190`).

Submitting creates the target row **and** starts the scan in one POST pair; the page redirects to the new scan's detail page where progress streams in live.

### 3. Scan Detail — live progress, findings, controls

![Scan detail](https://raw.githubusercontent.com/FitzyPrjkt/Redveil-UI/main/Mockup-Redveil/PYPI-shots/06-scan-detail.png)

The high-traffic page during a scan. Three things stream in:

1. **Status pill** (top): `pending` → `running` → `completed` / `failed`.
2. **Findings list** (mid): populates as the orchestrator emits them. Each row has severity, confidence, title, endpoint, and a `View` link.
3. **Event log** (right rail): per-action decisions from the `ActionGate` (auto-approve, denied, etc).

SSE connection: `GET /api/scans/{id}/stream` emits one event per orchestrator action with `: keep-alive` heartbeats every 15s. The Python backend uses a per-scan pub-sub (`redveil_ui/api/event_bus.py`) so the orchestrator can run independently of any open SSE clients — closing the tab does **not** cancel the scan.

### 4. Scan History — past runs at a glance

![Scan History](https://raw.githubusercontent.com/FitzyPrjkt/Redveil-UI/main/Mockup-Redveil/PYPI-shots/04-scans-list.png)

List of every scan the operator has run, ordered newest first. Filters: status (`all` / `running` / `completed` / `failed`) and free-text search across target URL + name. Click any row to go to that scan's detail page.

Stat tiles at the top show total scans, running count, and 7-day finding count. Empty state prompts the operator to start a new scan.

### 5. Dashboard — entry point

![Dashboard](https://raw.githubusercontent.com/FitzyPrjkt/Redveil-UI/main/Mockup-Redveil/PYPI-shots/01-dashboard.png)

Recent activity, stat tiles (total scans / active targets / 7-day findings), and quick links to create targets or review history. Sidebar nav gives one-click access to every section.

### 6. Target / Site Map — per-target endpoint inventory

![Target sitemap](https://raw.githubusercontent.com/FitzyPrjkt/Redveil-UI/main/Mockup-Redveil/PYPI-shots/10-target-sitemap.png)

Drill-down view for a single target: every endpoint the orchestrator
discovered during scans, grouped by folder, with per-endpoint finding
counts and severity histograms. Pulls from
`GET /api/targets/{id}/sitemap`.

### 7. Evidence Log — every request/response captured

![Evidence Log](https://raw.githubusercontent.com/FitzyPrjkt/Redveil-UI/main/Mockup-Redveil/PYPI-shots/07-evidence-log.png)

All `Evidence` objects written by the orchestrator during scans. Each row has the timestamp, endpoint, HTTP method, status code, body length, and a short body excerpt. Filterable by `method`, `check_id`, and `status_min`/`status_max`. Click a row to expand the full request/response.

This is the same evidence that powers the `ReplayEngine` and the
`confidence = oracle × (1 + log2(distinct_dims)) × weight − env_penalty − uncertainty` scoring in the underlying `redveil` library.

### 8. Finding Detail — investigate one finding

![Finding detail](https://raw.githubusercontent.com/FitzyPrjkt/Redveil-UI/main/Mockup-Redveil/PYPI-shots/08-finding-detail.png)

For a single finding: severity, confidence, CWE / OWASP tags,
`technical_explanation` (why the orchestrator marked this as a finding),
and `remediation` (what to do about it). The Replay button runs the
captured `ReplayRecipe` N times to verify reproducibility — see Replay
below.

### 9. Replay — verify reproducibility

![Replay](https://raw.githubusercontent.com/FitzyPrjkt/Redveil-UI/main/Mockup-Redveil/PYPI-shots/09-replay.png)

Takes the captured `ReplayRecipe` (request method + URL + body + headers) and re-issues it `N` times. If the timing-signal reproduces consistently, the finding's confidence is corroborated; if it flakes, the
finding is demoted. The `redveil` library's `ReplayEngine` runs the
samples; this UI just configures sample count and shows the verdict.

If the original finding has no `replay_recipe` (some checks don't
capture one — that's documented in the model), the Replay button is
hidden and a "Replay not available" callout shows why.

### 10. Probe Builder — manual targeted probing

![Probe Builder](https://raw.githubusercontent.com/FitzyPrjkt/Redveil-UI/main/Mockup-Redveil/PYPI-shots/11-probe-builder.png)

Operator-initiated probes, separate from the automatic checks. Two modes:

- **Preset** — pick a built-in check (e.g. `sqli-time-based`) and the
  client fetches its payload set from
  `GET /api/probes/payload-sets`. Select by index, no string input.
- **Custom** — write your own payload string. The form requires
  `confirmed_dwyor: true` in the POST body and the endpoint enforces
  this with `HTTP 403` if missing — the two-gate DWYOR confirmation
  (`Gate 1` expand to acknowledge, then `Gate 2` type-to-confirm).
  This is the "outside curated checks" path mentioned in the warning
  at the top of this README.

The Probe Builder reuses the same `HttpClient` + `ScopeController` as
the automatic checks, so the same scope/destructive-level rules apply.
A custom probe that violates scope is rejected by `HttpClient` with
`ScopeViolation` before any request is sent.

### 11. Plugins — 19 checks at a glance

![Plugins](https://raw.githubusercontent.com/FitzyPrjkt/Redveil-UI/main/Mockup-Redveil/PYPI-shots/12-plugins.png)

Read-only list of every check plugin discovered from the installed
`redveil` library via its `entry_points = redveil.checks` metadata. The
list comes from `GET /api/checks`. This is the same source the
orchestrator loads at scan start, so a 19-check install of `redveil`
shows 19 cards here, dynamically — no static copy.

### 12. Decoder + 13. Comparer + 14. Token Entropy — utility trio

| ![Decoder](https://raw.githubusercontent.com/FitzyPrjkt/Redveil-UI/main/Mockup-Redveil/PYPI-shots/13-decoder.png) | ![Comparer](https://raw.githubusercontent.com/FitzyPrjkt/Redveil-UI/main/Mockup-Redveil/PYPI-shots/14-comparer.png) | ![Token Entropy](https://raw.githubusercontent.com/FitzyPrjkt/Redveil-UI/main/Mockup-Redveil/PYPI-shots/15-token-entropy.png) |
| :---: | :---: | :---: |
| **Decoder** | **Comparer** | **Token Entropy** |
| Multi-format decode (base64, hex, URL, HTML entities, JWT split). | Side-by-side evidence diff for two captured requests. Calls `redveil.knowledge.Comparer` to diff structured fields. | Shannon entropy + per-token analysis. `POST /api/entropy/analyze`. |

### 15. Settings — the live config, not a hardcoded page

![Settings](https://raw.githubusercontent.com/FitzyPrjkt/Redveil-UI/main/Mockup-Redveil/PYPI-shots/16-settings.png)

Reads the same `~/.redveil-ui/config.yaml` that `redveil-ui init` wrote
and the server reads at startup. Every field shown here is the value
the running process is actually using (`host`, `port`, `data_dir`,
`reports_dir`, `gate_mode`, `max_destructive_level`, `allow_destructive`).
No fake / hardcoded values.

---

## why redveil-ui vs the CLI

| | `redveil-ui` (this package) | `redveil` CLI | Burp / Nessus / enterprise platforms |
|---|---|---|---|
| Interface | Browser dashboard, one port, real-time SSE | Terminal, exit code, JSON output | Heavy Java/Electron client, often paid |
| Hosting | 100% local, `127.0.0.1` by default | Your shell | Cloud / licensed server |
| State | SQLite at `~/.redveil-ui/data/` | Per-run directory under `reports/` | Project server, often remote |
| Probe library | Same 19 checks via the installed `redveil` library | Same 19 checks | Different ecosystems |
| Replay | One click in the UI | `redveil replay <report-dir>` | Manual via Intruder/Comparer |
| Cost | Free, MIT, self-hosted | Free, MIT, self-hosted | $400+/yr per seat |
| Best for | Solo operators running scans on their own schedule | CI / scripted / scripted | Teams with budget + need for shared state |

If you only run scans from cron or CI, the CLI is enough. If you want
to sit at a browser while a scan runs, see findings populate, dig into
evidence, and replay individual results, this is the interface.

---

## architecture

```
Browser (port 8000)
   │
   │ HTTP / SSE
   ▼
Uvicorn :8000 (single process)
   │
   ├─► FastAPI app (redveil_ui.api.main)
   │     ├─► /api/* routers
   │     │     ├─ /api/targets, /api/scans, /api/findings
   │     │     ├─ /api/checks, /api/probes/*
   │     │     ├─ /api/entropy/analyze
   │     │     └─ /api/scans/{id}/stream  (SSE)
   │     ├─► redveil_ui.api.event_bus (per-scan pub-sub for SSE)
   │     └─► Static SPA fallback: serves ui/frontend/out/{route}.html
   │           └─► React Router hydrates the rest
   │
   └─► redveil_ui.scanner (orchestrator)
         │
         │  imports from `redveil` (installed lib, version pinned ≥1.9.6)
         ▼
       redveil.orchestrator.run(scan)
         → redveil.http.HttpClient (with ScopeController)
         → redveil.plugins.check_registry
         → redveil.validation.ActionGate
         → redveil.reporting.markdown.write_report
         → redveil_ui.api.event_bus.publish (for SSE)
```

One port, one process, one SQLite file. The frontend is a static
export served by the same uvicorn. There is no separate API server, no
reverse proxy, no Redis, no Postgres.

---

## requirements

- **Python ≥ 3.11**
- **redveil ≥ 1.9.6** (auto-installed as a dependency)
- **~80 MB disk** for the wheel + transitive deps in a fresh venv
- A free TCP port (default `8000`; the init command picks the next free port if `8000` is taken)

`redveil` must be importable as `import redveil` — the dashboard will
fail-fast at startup if it isn't.

---

## status & roadmap

**0.1.0 is feature-complete for the documented surface.** All 15
routes render, all major actions work, 1101/1101 library tests pass,
19/19 dashboard e2e tests pass on a fresh install in a clean venv.

### known limitations (roadmap, not blockers)

- **`false_positive` UI toggle** — the API endpoint filters false positives by default with `?include_fp=true` opt-in, but the dashboard's Findings list doesn't expose the toggle yet. Filed for 0.2.0.
- **SQLite WAL mode + startup recovery sweep** — single-writer SQLite can lock under heavy write loads. No retry-on-lock in the current scanner. A WAL mode + `busy_timeout=5000` event-listener + startup-recovery sweep for orphan `'running'` scans is filed for 0.2.0.
- **`max_requests` UI in scan list** — server-side cap (`Field(gt=0, le=100000)`) is enforced; per-scan row display in `/scans` doesn't surface it. Cosmetic.
- **Empty-state contract** — list endpoints return `[]` for empty DB; `/api/scans/{id}/evidence` returns `404` (not `[]`) for an unknown scan id. UI handles both. Maybe align to `[]` in 0.2.0.
- **e2e_lab + negative_testing tests** are backend integration tests shipped with the `redveil` library. They run cleanly (`8 + 4 = 12 pass`) and are listed in the library's CI, not the dashboard's acceptance criteria.

### security posture (relevant for review)

The `redveil-ui` API applies the same safety checks as the `redveil` CLI:

- **URL safety** (always-blocked at the schema layer): `file://`, `ftp://`, `javascript:`, `data:`, `169.254.0.0/16` (incl. AWS IMDS), `168.63.129.16` (Azure WireServer), `metadata.google.internal` (GCP). RFC1918 + loopback are allowed but must be in the target's `allowed_hosts` scope.
- **Scope check** runs synchronously at scan creation. Out-of-scope scan → `403`, scan never starts.
- **Destructive level**: `L3+` requires `allow_destructive: true`. Refusal is `422` with a clear message.
- **Probe Builder** requires `confirmed_dwyor: true` in the body, validated server-side.
- **YAML parse failure** in `scope_yaml` is a hard error (rejected with `422`), not a silent fallback to "allow everything".
- **Loopback default**: server binds `127.0.0.1` only. LAN exposure requires a config edit.

---

## see also

- **[redveil](https://pypi.org/project/redveil/)** — the underlying scanning library. `redveil-ui` is a thin operational layer over it.
- **[FitzyPrjkt/Redveil](https://github.com/FitzyPrjkt/Redveil)** — full source tree (library + UI + docs in one monorepo).
- **`USER_GUIDE.md`** — detailed walkthrough of CLI install + scan invocation.
- **`CONTRIBUTING.md`** — how to add a new check plugin.
- **`SECURITY.md`** — full safety model and how to report issues.

## license

**Proprietary, NOT open source.** See [`LICENSE`](https://github.com/FitzyPrjkt/Redveil-UI/blob/main/LICENSE).

What you **can** do without asking:
- Self-host the unmodified `redveil-ui` package for your own use.

What you **cannot** do without written permission from the copyright holder:
- Redistribute, mirror, or ship the package through any channel other than the official PyPI release.
- Modify, adapt, translate, or create derivative works.
- Rebrand, repackage, or remove the copyright / license notices.
- Use the names `redveil`, `redveil-ui`, or any confusingly similar name on derivative products.
- Commercial use, sale, or sublicensing.

If you want a different arrangement (commercial license, derivative
work, OEM bundling, etc.) — contact the copyright holder.
