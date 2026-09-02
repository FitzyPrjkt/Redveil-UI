# WPOC-64D77C: Subdomain Discovered: 127.0.0.1

**Severity:** INFO  
**Confidence:** HIGH  
**Status:** CONFIRMED  

**Affected endpoint:** `HEAD https://127.0.0.1/`
**Input used:** `127.0.0.1`

## Summary

Discovered subdomain '127.0.0.1' of '127.0.0.1' while crawling the site. The crawler visited 9 page(s) and inspected 11 URL(s); '127.0.0.1' was referenced by one of those URLs.

## Technical explanation

Root domain: 127.0.0.1. Discovery source: crawl. Hostname observed: 127.0.0.1.

## Steps to reproduce

1. Issue HEAD https://127.0.0.1/ — expect a 2xx/3xx response (proves the host is alive).
   ```
   curl -X HEAD https://127.0.0.1/
   ```
2. Confirm the hostname is a subdomain of the target via DNS: dig +short 127.0.0.1
   ```
   dig +short 127.0.0.1
   ```

## Impact

Each discovered subdomain expands the attack surface of the target organization. Subdomains sometimes run outdated software, dev/staging tools, or admin panels with weaker controls than the production site. Even passive discovery (DNS lookup or HEAD probe) is enough to enumerate the surface for follow-up review.

## Evidence

_1 evidence record(s). See `evidence/WPOC-64D77C-*.txt` in the report directory._

## Remediation

1. Maintain an authoritative inventory of all subdomains and decommission anything not actively used.
2. Apply the same hardening (HTTPS, headers, auth) to every subdomain, including dev/staging environments.
3. Use DNS zone files and certificate-transparency logs to detect subdomain takeover risk before an attacker does.

## References

- OWASP A05:2021
- https://owasp.org/www-project-attack-surface-management/

---
*Discovered: 2026-08-31T22:07:11.417266+00:00*  
*Tool: redveil v0.1.0*