# WPOC-79FBB9: Exposed Debug Endpoint

**Severity:** HIGH  
**Confidence:** HIGH  
**Status:** CONFIRMED  

**Affected endpoint:** `GET http://127.0.0.1/debug`
**Parameter:** `body`
**Input used:** `/debug`

## Summary

A debug endpoint (`/debug`, `/api/_debug`, `/admin/debug`) is reachable without authentication and returns runtime internals — Python version, Flask routes, environment variables, active sessions, sometimes even direct database access. Debug endpoints are intended for development and should never be exposed in production.

## Technical explanation

Debug endpoints are commonly added by frameworks in development mode (Flask `/debug`, Django Debug Toolbar) or by developers as a quick way to inspect application state. They return rich internal data: route maps, environment variables, request context, database queries, sometimes even admin actions. Werkzeug's interactive debugger (when `debug=True`) is a remote code execution vulnerability if exposed — the debugger console accepts arbitrary Python code. Even non-interactive debug endpoints leak enough information to mount targeted attacks.

## Attack scenario

1. Attacker runs a directory brute force and finds `/debug` returning 200
2. Response contains the full route map (every URL the app serves), Flask version, all environment variables including API keys, and the Python version
3. Attacker maps the route list to known CVEs for that framework version
4. Attacker reads API keys from env vars and uses them to access the database, payment processor, or cloud provider
5. With Werkzeug debug enabled, attacker executes arbitrary Python in the application context — full RCE

## Steps to reproduce


## Impact

Critical disclosure of internal state. At minimum, route maps and config reveal attack surface; at worst, exposed debug endpoints enable remote code execution (Werkzeug, Tornado, Rails `better_errors`). Even a benign debug page that returns request headers can leak Authorization tokens if a downstream service forwards them.

## Evidence

_1 evidence record(s). See `evidence/WPOC-79FBB9-*.txt` in the report directory._

## Remediation

1. Remove or disable all debug endpoints in production: in Flask, `app.debug = False` and `use_debugger = False`.
2. Add an environment-based guard: only register the debug blueprint when `app.config['ENV'] == 'development'`.
3. Block access at the reverse proxy: `location /debug { deny all; }`.
4. Audit route maps for `/debug`, `/_debug`, `/admin/debug`, `/__debug__`, and similar patterns.

## Code examples

### flask

```
if app.config['ENV'] == 'development':
    from myapp.debug import debug_bp
    app.register_blueprint(debug_bp)
# Werkzeug debugger: never enable in production
app.run(debug=False)
```

### django

```
# settings.py
DEBUG = False
# Never install django-debug-toolbar in production
# INSTALLED_APPS should not contain 'debug_toolbar'
```

### express

```
if (process.env.NODE_ENV !== 'production') {
  app.get('/debug', require('./routes/debug'));
}
```

### nginx

```
location ~ ^/(debug|_debug|admin/debug|__debug__) {
    deny all;
    return 404;
}
```

### generic

```
# CI check:
grep -rn 'app.run(.*debug' src/ && exit 1
grep -rn '/debug' src/routes/ && exit 1
```

## References

- CWE-200 (https://cwe.mitre.org/data/definitions/200.html)
- OWASP A01:2021

---
*Discovered: 2026-08-31T22:06:56.626161+00:00*  
*Tool: redveil v0.1.0*