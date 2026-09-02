# WPOC-7D85A3: Missing Referrer-Policy Header

**Severity:** LOW  
**Confidence:** HIGH  
**Status:** CONFIRMED  

**Affected endpoint:** `GET http://127.0.0.1/`
**Parameter:** `referrer-policy`
**Input used:** `(not set)`

## Summary

The Referrer-Policy header is set to `unsafe-url` or `no-referrer-when-downgrade`, allowing the browser to send the full URL of the current page (including path and query parameters) to any external site the user navigates to. Query parameters often contain session tokens, search terms, or other sensitive data.

## Technical explanation

When a user clicks an outbound link or loads an external resource, the browser sends the Referer header — the URL of the current page. `unsafe-url` sends the full URL regardless of protocol. `no-referrer-when-downgrade` sends the full URL to any destination as long as the destination is HTTPS (or HTTP, matching the source). Both leak sensitive path/query information. Safer values are `strict-origin-when-cross-origin` (default in modern browsers), `same-origin` (only same-origin requests get the full URL), or `no-referrer` (never send).

## Attack scenario

1. Application uses URL parameters to pass state, e.g. `/reset-password?token=abc123`
2. Application does not set Referrer-Policy, so the browser defaults to `strict-origin-when-cross-origin` (or worse, an unsafe value)
3. Victim loads the page, then clicks an outbound link to any third-party site (a forum, a help doc, etc.)
4. The third-party site receives `Referer: https://target.example/reset-password?token=abc123`
5. If the third party is malicious or compromised, the reset token is now in the access logs

## Steps to reproduce


## Impact

Leakage of sensitive URL parameters (password reset tokens, internal search queries, file paths, debug flags) to any external destination the user visits. Many analytics platforms, ad networks, and partner sites collect Referer headers as a matter of routine — the data spreads quickly beyond your control.

## Evidence

_1 evidence record(s). See `evidence/WPOC-7D85A3-*.txt` in the report directory._

## Remediation

1. Set `Referrer-Policy: strict-origin-when-cross-origin` (modern default) or stricter: `same-origin`, `no-referrer`, or `same-origin-strict-origin`.
2. Avoid putting secrets in URLs altogether — use POST bodies for sensitive state.
3. Audit existing usage of `unsafe-url` and `no-referrer-when-downgrade` in legacy configurations.

## Code examples

### nginx

```
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

### apache

```
Header always set Referrer-Policy "strict-origin-when-cross-origin"
```

### express

```
app.use((req, res, next) => {
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});
```

### flask

```
@app.after_request
def set_rp(resp):
    resp.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return resp
```

### django

```
SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'
```

## References

- CWE-693 (https://cwe.mitre.org/data/definitions/693.html)
- OWASP A05:2021

---
*Discovered: 2026-08-31T22:06:59.630715+00:00*  
*Tool: redveil v0.1.0*