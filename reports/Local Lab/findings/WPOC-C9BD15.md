# WPOC-C9BD15: Missing Permissions-Policy Header

**Severity:** LOW  
**Confidence:** HIGH  
**Status:** CONFIRMED  

**Affected endpoint:** `GET http://127.0.0.1/`
**Parameter:** `permissions-policy`
**Input used:** `(not set)`

## Summary

The Permissions-Policy header is not set, allowing all embedded iframes, scripts, and images full access to powerful browser APIs such as camera, microphone, geolocation, and USB. While the policy is opt-in rather than blocking, its absence means a third-party script can quietly request access without your site's consent.

## Technical explanation

Permissions-Policy (formerly Feature-Policy) is a response header that lets a site declare which browser features are allowed for the page and for any embedded content. Examples: `camera=(), microphone=(), geolocation=(self), usb=()`. When absent, the browser default is to permit everything. A third-party analytics script or ad tag can request `navigator.mediaDevices.getUserMedia()` without the host page's explicit policy, and the browser will prompt the user (or silently allow in some legacy contexts).

## Attack scenario

1. Application includes a third-party analytics script (analytics.example.com)
2. analytics.example.com is compromised or rebranded into a malicious network
3. Malicious script calls `navigator.geolocation.getCurrentPosition()` and exfiltrates the user's coordinates
4. Or calls `navigator.usb.requestDevice()` to enumerate connected USB devices
5. With `Permissions-Policy: geolocation=(), camera=()` set, the browser blocks these APIs entirely for the page and any embedded content

## Steps to reproduce


## Impact

Reduced control over which browser features are exposed to first-party code, embedded iframes, and third-party scripts. Particularly relevant for sites serving content from ad networks, embedded videos, or chat widgets. Defense in depth: if a third-party tag is compromised, Permissions-Policy limits the blast radius.

## Evidence

_1 evidence record(s). See `evidence/WPOC-C9BD15-*.txt` in the report directory._

## Remediation

1. Add a Permissions-Policy header that disables features you do not use: `Permissions-Policy: camera=(), microphone=(), geolocation=(), usb=(), payment=()`. Allow specific origins only for the features you need: `geolocation=(self)`.
2. Audit embedded third-party scripts and tags; tighten policies to limit what each embedded origin can do.
3. Test changes incrementally — some legacy code may rely on a feature you decide to disable.

## Code examples

### nginx

```
add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), usb=()" always;
```

### apache

```
Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"
```

### express

```
app.use((req, res, next) => {
  res.setHeader(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=()'
  );
  next();
});
```

### flask

```
@app.after_request
def set_pp(resp):
    resp.headers['Permissions-Policy'] = 'camera=(), microphone=()'
    return resp
```

### django

```
# No built-in setting; use middleware:
response['Permissions-Policy'] = 'camera=(), microphone=()'
```

## References

- CWE-693 (https://cwe.mitre.org/data/definitions/693.html)
- OWASP A05:2021

---
*Discovered: 2026-08-31T22:06:59.642457+00:00*  
*Tool: redveil v0.1.0*