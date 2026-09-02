# WPOC-E7D420: Exposed Management Panel

**Severity:** MEDIUM  
**Confidence:** HIGH  
**Status:** CONFIRMED  

**Affected endpoint:** `GET http://127.0.0.1/server-status`
**Parameter:** `body`
**Input used:** `/server-status`

## Summary

A management or status panel (`/server-status`, `/server-info`, `/phpinfo.php`) is publicly accessible. These panels reveal active connections, request logs, server configuration, and loaded modules. Apache `server-status` is a frequent find — it lists every recent request including URLs that may not be linked from the main site.

## Technical explanation

Apache `mod_status` exposes `/server-status` showing recent requests, worker status, and connection counts. `/server-info` lists every loaded module with version info. PHP `phpinfo()` dumps every PHP setting, environment variable, and module — a goldmine for attackers. These endpoints are often enabled by default in development configurations and accidentally deployed to production.

## Attack scenario

1. Attacker requests `/server-status` — Apache returns the last 100 requests including IPs, URLs, and user agents
2. Attacker discovers URLs not linked anywhere on the site: `/admin/legacy-import`, `/internal/sync`, `/api/v2/debug`
3. Attacker enumerates these hidden endpoints for further vulnerabilities
4. `/phpinfo.php` reveals `DOCUMENT_ROOT`, `_SERVER['SERVER_ADMIN']`, the loaded PHP extensions and versions — direct CVE matching
5. Attacker now has a complete map of the server's attack surface

## Steps to reproduce


## Impact

Reconnaissance shortcut. Apache `server-status` lists recent requests including those to admin or internal endpoints. `phpinfo()` leaks the full PHP configuration including credentials, document root, and library versions. Once an attacker has these, every subsequent attack is targeted rather than blind.

## Evidence

_1 evidence record(s). See `evidence/WPOC-E7D420-*.txt` in the report directory._

## Remediation

1. Disable Apache `mod_status` or restrict it to localhost: `<Location /server-status> Require ip 127.0.0.1 </Location>`.
2. Remove `phpinfo.php` from production; never deploy it.
3. Block these paths at the reverse proxy: `location ~ ^/(server-status|server-info|phpinfo\.php) { deny all; }`.
4. Audit your `httpd.conf` for `SetHandler server-status` and your codebase for `phpinfo()` calls.

## Code examples

### apache

```
<Location "/server-status">
    SetHandler server-status
    Require local  # or Require ip 127.0.0.1
</Location>
<Location "/server-info">
    SetHandler server-info
    Require local
</Location>
```

### nginx

```
location ~ ^/(server-status|server-info|phpinfo\.php) {
    deny all;
    return 404;
}
```

### php

```
# Search and remove phpinfo() calls:
grep -rn 'phpinfo()' src/ public/ && exit 1
# Or guard with:
if (\$_SERVER['REMOTE_ADDR'] !== '127.0.0.1') { phpinfo(); }
```

### deployment

```
# CI check: ensure phpinfo.php never lands in production
test ! -f /var/www/html/phpinfo.php
```

### flask

```
# Never expose Werkzeug's interactive debugger:
app.run(debug=False, host='127.0.0.1')
```

## References

- CWE-200 (https://cwe.mitre.org/data/definitions/200.html)
- OWASP A01:2021

---
*Discovered: 2026-08-31T22:06:56.637362+00:00*  
*Tool: redveil v0.1.0*