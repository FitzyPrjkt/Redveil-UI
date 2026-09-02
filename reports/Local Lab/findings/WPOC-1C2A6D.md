# WPOC-1C2A6D: Exposed Source Map File

**Severity:** MEDIUM  
**Confidence:** HIGH  
**Status:** CONFIRMED  

**Affected endpoint:** `GET http://127.0.0.1/api/source-map`
**Parameter:** `body`
**Input used:** `/api/source-map`

## Summary

A JavaScript source map file (`*.js.map`) is publicly accessible. Source maps translate minified production code back to the original source — including comments, internal variable names, and unreleased features. An attacker who fetches the map sees your application as if it were open source.

## Technical explanation

Modern build tools (Webpack, Vite, esbuild, Rollup) generate source maps by default. They map positions in the minified production bundle back to lines in the original TypeScript or JavaScript. The `sourcesContent` array in the map contains the full original source. When deployed, attackers fetch the map and reconstruct comments, function names, dead code paths, and internal API URLs. Source maps should never be deployed to production — they should only be uploaded to error-tracking services (Sentry, Bugsnag) for stack-trace symbolication.

## Attack scenario

1. Attacker loads the application, opens DevTools, finds `/static/js/main.bundle.js`
2. Attacker fetches `/static/js/main.bundle.js.map` — returns 200 OK
3. Attacker reads the `sourcesContent` array — full original TypeScript source
4. Attacker finds comments like `// TODO: remove admin backdoor in v2.5`, internal endpoint URLs (`/api/internal/users`), hard-coded test credentials, or feature flags for unreleased features
5. Attacker exploits the discovered information — calls the internal endpoint, uses the credentials, or accesses an unfinished feature

## Steps to reproduce


## Impact

Full source code disclosure of the JavaScript bundle. While the minified code is already public (the bundle ships to every browser), the source map adds comments, variable names, and internal structure. Common leaks: API keys committed by developers, internal-only endpoints, hard-coded test credentials, comments referencing planned security controls or known issues. For applications with TypeScript types, the map can reveal the entire type system.

## Evidence

_1 evidence record(s). See `evidence/WPOC-1C2A6D-*.txt` in the report directory._

## Remediation

1. Do not deploy source maps to production. In Webpack: `devtool: 'hidden-source-map'` uploads the map to your error tracker but does not reference it from the bundle.
2. Or strip the `sourceMappingURL` comment from the production output: `devtool: false` or use `TerserPlugin` with `sourceMap: false`.
3. Block `.map` files at the web server: `location ~* \.map$ { deny all; return 404; }`.
4. If source maps must be accessible for debugging, restrict access via authentication or a private CDN accessible only to your error-tracking service.

## Code examples

### webpack

```
// webpack.config.js
module.exports = {
  // Production: do not bundle source map into output
  devtool: false,
  // Or: upload to Sentry without serving to clients
  devtool: 'hidden-source-map',
  plugins: [new SentryWebpackPlugin({ ... })],
};
```

### vite

```
// vite.config.ts
export default defineConfig({
  build: {
    sourcemap: false,  // or 'hidden' for error tracker only
  }
});
```

### nginx

```
location ~* \.map$ {
    deny all;
    return 404;
}
```

### apache

```
<FilesMatch "\.map$">
    Require all denied
</FilesMatch>
```

### express

```
app.use((req, res, next) => {
  if (/\.map$/.test(req.path)) return res.status(404).end();
  next();
});
```

## References

- CWE-200 (https://cwe.mitre.org/data/definitions/200.html)
- OWASP A01:2021

---
*Discovered: 2026-08-31T22:06:56.647776+00:00*  
*Tool: redveil v0.1.0*