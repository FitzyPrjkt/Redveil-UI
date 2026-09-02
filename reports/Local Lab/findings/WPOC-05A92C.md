# WPOC-05A92C: Wildcard CORS Origin Combined With Credentials

**Severity:** CRITICAL  
**Confidence:** HIGH  
**Status:** CONFIRMED  

**Affected endpoint:** `OPTIONS http://127.0.0.1/api/data`
**Parameter:** `Origin`
**Input used:** `https://evil.example`

## Summary

The server sets both `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Credentials: true`. Modern browsers refuse to honor this combination, but misconfigured CDNs, reverse proxies, or non-browser clients can strip the wildcard check and treat the configuration as if any origin is allowed with credentials. This is a CRITICAL misconfiguration.

## Technical explanation

Per the CORS specification, the `*` wildcard is incompatible with `Access-Control-Allow-Credentials: true`. Browsers refuse to send or honor the response, returning a console error. However, middleware that strips the credentials header (or that does not know about the CORS spec — older proxies, CDNs in legacy mode, non-browser HTTP clients) may still apply the wildcard and successfully process credentialed requests. The result is the same as origin reflection but is harder to detect because the origin 'mismatch' is invisible to the client.

## Attack scenario

1. Application behind a CDN that strips ACAO credentials mismatch checks (or a non-browser client like a mobile app using a WebView that doesn't enforce the spec)
2. Backend sets `Access-Control-Allow-Origin: *` and `Access-Control-Allow-Credentials: true`
3. Attacker hosts https://evil.example and uses a non-standard client or bypass to issue credentialed XHR
4. CDN forwards the request with the victim's cookies; backend responds with `*` and credentials
5. Attacker reads the response
6. Or simpler: the application is served from both a browser context (where the spec protects) and a non-browser context (where it doesn't) — attacker exploits the latter

## Steps to reproduce

1. Send an OPTIONS preflight to http://127.0.0.1:5000/api/data with Origin: https://evil.example.
   ```
   curl -X OPTIONS -H 'Origin: https://evil.example' -H 'Access-Control-Request-Method: GET' http://127.0.0.1:5000/api/data
   ```
2. Observe Access-Control-Allow-Origin: *

## Impact

Critical credentialed data exposure. When the spec is enforced the impact is reduced to a console error, but any environment where the spec is not enforced — a CDN, a proxy, an embedded WebView, a native mobile client — is exposed. This is a recurring real-world finding in bug bounty programs precisely because it survives the standard browser defenses.

## Evidence

_2 evidence record(s). See `evidence/WPOC-05A92C-*.txt` in the report directory._

## Remediation

1. Never combine `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`. Replace `*` with an explicit allowlist of trusted origins.
2. Audit the full stack — CDN, reverse proxy, load balancer — for places where the CORS spec enforcement is bypassed.
3. If you need credentialed CORS, respond with the specific matching origin (after allowlist check) and set credentials to true only for that origin.
4. Use Content-Security-Policy to further restrict which origins can frame or include your content.

## Code examples

### nginx

```
# NEVER do this:
# add_header Access-Control-Allow-Origin "*" always;
# add_header Access-Control-Allow-Credentials "true" always;
# Use a specific origin instead:
map $http_origin $cors_allow {
    default "";
    "https://app.example.com" "https://app.example.com";
}
add_header Access-Control-Allow-Origin $cors_allow always;
add_header Access-Control-Allow-Credentials "true" always;
```

### apache

```
# Use SetEnvIf to restrict and never set ACAO to literal "*"
SetEnvIf Origin "^https://app\.example\.com$" CORS_OK
Header set Access-Control-Allow-Origin "%{CORS_OK}e" env=CORS_OK
Header set Access-Control-Allow-Credentials "true" env=CORS_OK
```

### express

```
const ALLOW = ['https://app.example.com'];
app.use((req, res, next) => {
  if (ALLOW.includes(req.headers.origin)) {
    res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  }
  next();
});
```

### flask

```
from flask_cors import CORS
CORS(app, origins=['https://app.example.com'], supports_credentials=True)
```

### django

```
CORS_ALLOWED_ORIGINS = ['https://app.example.com']
CORS_ALLOW_CREDENTIALS = True  # with specific origins only
```

## References

- CWE-942 (https://cwe.mitre.org/data/definitions/942.html)
- OWASP A05:2021
- https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS
- https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny

---
*Discovered: 2026-08-31T22:06:31.084179+00:00*  
*Tool: redveil v0.1.0*