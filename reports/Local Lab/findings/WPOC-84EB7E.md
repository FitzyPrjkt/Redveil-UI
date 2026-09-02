# WPOC-84EB7E: Version Disclosure in Server Header

**Severity:** MEDIUM  
**Confidence:** HIGH  
**Status:** CONFIRMED  

**Affected endpoint:** `GET http://127.0.0.1/`
**Parameter:** `server`
**Input used:** `Werkzeug/3.1.8 Python/3.13.5`

## Summary

The response includes a `Server` or `X-Powered-By` header that discloses the exact software version (e.g. `nginx/1.18.0`, `Express`, `PHP/7.4.3`). Public vulnerability databases index every version of every web server; advertising yours lets an attacker look up CVEs that match your stack without doing any reconnaissance themselves.

## Technical explanation

Web servers and frameworks often auto-add headers identifying themselves. `Server` is set by Apache, nginx, IIS. `X-Powered-By` is set by PHP, ASP.NET, Express. Exact version strings are even more valuable than names. Tools like Shodan, Censys, and vulnerability scanners ingest these headers at scale to build asset inventories and CVE match lists. Removing the version (or the header entirely) gives an attacker one more step to perform before they can target specific CVEs.

## Attack scenario

1. Attacker runs a port scan on the target's IP range
2. Server responds with `Server: nginx/1.14.0`
3. Attacker searches `https://vulners.com/search?query=nginx+1.14.0` and discovers CVE-2019-20372 (error_page request smuggling)
4. Attacker checks the target's exact version against the CVE's affected list — match
5. Attacker fires off the exploit without further recon
6. Without the version, the attacker would have to fingerprint manually or try broader exploits

## Steps to reproduce


## Impact

Faster, more reliable target identification by adversaries. Specific CVEs can be matched to your stack without active probing. In large-scale attacks (botnets, worms), version-specific exploits are launched automatically. Disclosing versions also signals to attackers whether you're running an outdated stack — a strong indicator of broader security hygiene issues.

## Evidence

_1 evidence record(s). See `evidence/WPOC-84EB7E-*.txt` in the report directory._

## Remediation

1. Set `server_tokens off;` in nginx to remove the version from the Server header.
2. In Apache, set `ServerTokens Prod` (and `ServerSignature Off`) to emit only `Server: Apache`.
3. In Express, call `app.disable('x-powered-by')` to remove `X-Powered-By: Express`.
4. In IIS, configure `removeServerHeader=true` via web.config.
5. Strip or rewrite these headers at the reverse proxy as a defense-in-depth measure.

## Code examples

### nginx

```
server_tokens off;  # in http {} or server {} block
```

### apache

```
ServerTokens Prod
ServerSignature Off
```

### express

```
const app = express();
app.disable('x-powered-by');
```

### iis

```
<!-- web.config -->
<system.webServer>
  <security>
    <requestFiltering removeServerHeader="true" />
  </security>
</system.webServer>
```

### flask

```
@app.after_request
def strip_server(resp):
    resp.headers.pop('Server', None)
    resp.headers.pop('X-Powered-By', None)
    return resp
```

## References

- CWE-200 (https://cwe.mitre.org/data/definitions/200.html)
- OWASP A01:2021

---
*Discovered: 2026-08-31T22:06:56.592884+00:00*  
*Tool: redveil v0.1.0*