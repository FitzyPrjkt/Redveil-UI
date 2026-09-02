# redveil Security Assessment — Local Lab

**Generated:** 2026-08-31T22:07:11.426965+00:00  
**Findings:** 14  

## Summary by severity

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 1 |
| 🟠 HIGH | 2 |
| 🟡 MEDIUM | 6 |
| 🟢 LOW | 4 |
| 🔵 INFO | 1 |

## Findings

- [🟠 HIGH] **CORS Origin Reflection Without Validation** — /api/data (confidence: high)
- [🔴 CRITICAL] **Wildcard CORS Origin Combined With Credentials** — /api/data (confidence: high)
- [🟡 MEDIUM] **Version Disclosure in Server Header** — / (confidence: high)
- [🟠 HIGH] **Exposed Debug Endpoint** — /debug (confidence: high)
- [🟡 MEDIUM] **Exposed Management Panel** — /server-status (confidence: high)
- [🟡 MEDIUM] **Exposed Source Map File** — /api/source-map (confidence: high)
- [🟢 LOW] **Potential Open Redirect via 'to' Parameter** — /redirect (confidence: low)
- [🟡 MEDIUM] **Missing Content-Security-Policy Header** — / (confidence: high)
- [🟡 MEDIUM] **Missing X-Frame-Options Header** — / (confidence: high)
- [🟢 LOW] **Missing X-Content-Type-Options Header** — / (confidence: high)
- [🟡 MEDIUM] **Missing Strict-Transport-Security Header** — / (confidence: high)
- [🟢 LOW] **Missing Referrer-Policy Header** — / (confidence: high)
- [🟢 LOW] **Missing Permissions-Policy Header** — / (confidence: high)
- [🔵 INFO] **Subdomain Discovered: 127.0.0.1** — / (confidence: high)
