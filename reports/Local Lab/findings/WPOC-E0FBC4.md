# WPOC-E0FBC4: Missing X-Frame-Options Header

**Severity:** MEDIUM  
**Confidence:** HIGH  
**Status:** CONFIRMED  

**Affected endpoint:** `GET http://127.0.0.1/`
**Parameter:** `x-frame-options`
**Input used:** `(not set)`

## Summary

The X-Frame-Options header is not set, which means the response can be embedded inside a <frame>, <iframe>, <embed>, or <object> on any other website. This enables clickjacking attacks where victims are tricked into clicking hidden elements rendered in their authenticated session.

## Technical explanation

Browsers consult the X-Frame-Options header (and the modern Content-Security-Policy ``frame-ancestors`` directive) to decide whether a page may be rendered inside a frame on another origin. When neither is present, browsers default to allowing framing from any origin. An attacker hosts your application inside an invisible iframe overlaid with attacker-controlled UI; the victim interacts with the framed page believing they are interacting with the attacker's surface, but every action executes inside their authenticated session on your application.

## Attack scenario

1. Attacker hosts a page at https://evil.example with an invisible iframe pointing to https://target.example/account/settings
2. The iframe is styled with opacity:0.001 and overlaid with a decoy UI such as a fake captcha or 'Watch Video' button
3. Victim visits https://evil.example while logged into target.example in the same browser
4. Victim clicks what appears to be 'Watch Video' but is actually the 'Delete Account' button underneath
5. The destructive action executes in the victim's authenticated session and the victim never sees anything wrong

## Steps to reproduce


## Impact

Clickjacking can be used to trick users into making unwanted financial transfers, changing account settings (recovery email, password, 2FA), granting OAuth or app permissions, deleting data, or following/unfollowing accounts. Severity escalates significantly when the framed page contains state-changing forms and the application lacks CSRF protection, because the click is interpreted as an intentional user action.

## Evidence

_1 evidence record(s). See `evidence/WPOC-E0FBC4-*.txt` in the report directory._

## Remediation

1. Add the header `X-Frame-Options: DENY` (most restrictive) or `SAMEORIGIN` if you legitimately embed your own pages in frames.
2. Prefer the modern equivalent: Content-Security-Policy with `frame-ancestors 'none'` or `frame-ancestors 'self'`. CSP frame-ancestors supersedes X-Frame-Options in all modern browsers.
3. Combine with a same-origin check on every state-changing form: if the request's Origin or Referer does not match your application, reject it (defense in depth against CSRF).

## Code examples

### nginx

```
add_header X-Frame-Options "SAMEORIGIN" always;
```

### apache

```
Header always set X-Frame-Options "SAMEORIGIN"
```

### express

```
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  next();
});
```

### flask

```
from flask import Flask
app = Flask(__name__)
@app.after_request
def set_xfo(resp):
    resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
    return resp
```

### django

```
# settings.py — use django-security or set in middleware:
SECURE_CONTENT_TYPE_NOSNIFF = True
X_FRAME_OPTIONS = 'SAMEORIGIN'  # django >= 4.0
# Or install django-security and add:
# 'security.middleware.XFrameOptionsMiddleware'
```

## References

- CWE-1021 (https://cwe.mitre.org/data/definitions/1021.html)
- OWASP A05:2021

---
*Discovered: 2026-08-31T22:06:59.596209+00:00*  
*Tool: redveil v0.1.0*