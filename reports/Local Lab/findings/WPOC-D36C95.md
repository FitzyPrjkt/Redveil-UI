# WPOC-D36C95: Missing Strict-Transport-Security Header

**Severity:** MEDIUM  
**Confidence:** HIGH  
**Status:** CONFIRMED  

**Affected endpoint:** `GET http://127.0.0.1/`
**Parameter:** `strict-transport-security`
**Input used:** `(not set)`

## Summary

The Strict-Transport-Security header is not set, so browsers will not enforce HTTPS for this domain. A network attacker on the same Wi-Fi, performing a man-in-the-middle attack, can intercept the first request to the site and serve HTTP content, capture session cookies, or inject content.

## Technical explanation

HSTS tells the browser: 'for this domain, never speak HTTP — always use HTTPS for the next N seconds.' On the first visit, the browser sees the HSTS header on an HTTPS response and pins the policy for `max-age` seconds. On subsequent visits, even if the user types `http://` or clicks an `http://` link, the browser silently upgrades to HTTPS before issuing the request. Without HSTS, an attacker who intercepts the very first request — or any request after the policy expires — can serve content over HTTP, strip TLS, or redirect to a phishing site. This is the classic sslstrip attack vector.

## Attack scenario

1. Victim joins coffee-shop Wi-Fi. Attacker on same network runs an ARP-spoofing / sslstrip tool
2. Victim types `target.example` in the address bar — no scheme, browser tries HTTP first
3. Attacker intercepts the plaintext HTTP request, strips the redirect-to-HTTPS, and proxies to the real site over HTTPS while serving an HTTP response to the victim
4. Victim logs in: attacker captures credentials or session cookies in plaintext
5. With HSTS `max-age=31536000` set on a previous session, the browser would have refused the HTTP request and upgraded to HTTPS before any attacker-controlled hop

## Steps to reproduce


## Impact

Credential theft via sslstrip, session hijacking, and forced downgrade to plaintext HTTP. Particularly damaging for sites that set session cookies without the Secure flag — those cookies leak in plaintext over the intercepted HTTP. HSTS also protects against cookie theft via misconfigured TLS terminators and stray http:// links in legacy systems.

## Evidence

_1 evidence record(s). See `evidence/WPOC-D36C95-*.txt` in the report directory._

## Remediation

1. Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` to every HTTPS response.
2. `max-age` of at least 1 year (31536000) is recommended; less than 6 months is flagged by security headers scanners.
3. Submit your domain to the HSTS preload list (https://hstspreload.org) so the policy is baked into browsers before the first visit.
4. Ensure all subdomains serve HTTPS — `includeSubDomains` is dangerous if any subdomain is HTTP-only.

## Code examples

### nginx

```
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
```

### apache

```
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
```

### express

```
app.use((req, res, next) => {
  res.setHeader(
    'Strict-Transport-Security',
    'max-age=31536000; includeSubDomains; preload'
  );
  next();
});
```

### flask

```
from flask_talisman import Talisman
Talisman(app, strict_transport_security=True, strict_transport_security_max_age=31536000, strict_transport_security_include_subdomains=True, strict_transport_security_preload=True)
```

### django

```
# settings.py
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True
# Requires SECURE_SSL_REDIRECT = True and SECURE_PROXY_SSL_HEADER
```

## References

- CWE-319 (https://cwe.mitre.org/data/definitions/319.html)
- OWASP A05:2021

---
*Discovered: 2026-08-31T22:06:59.619477+00:00*  
*Tool: redveil v0.1.0*