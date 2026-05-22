## Title
JavaScript Source Map Exposed on help.koho.ca — 1,315 Source Files Accessible

## Severity
Medium

## Summary
The knowledge base at `help.koho.ca` exposes JavaScript source maps that reveal the complete original source code of the application. The source map contains 1,315 files including application logic, API endpoints, and internal component structure.

## Steps to Reproduce
1. Navigate to: `https://help.koho.ca/kb-core.07a58674426ca7a4300a.js.map`
2. The full webpack source map is returned (2.4MB)
3. The map contains all original source files before minification

## PoC

```bash
curl -sk "https://help.koho.ca/kb-core.07a58674426ca7a4300a.js.map" | python3 -c "
import json, sys
data = json.load(sys.stdin)
print(f'Sources: {len(data[\"sources\"])} files')
for s in data['sources'][:10]:
    print(f'  {s}')
"
```

**Output:**
```
Sources: 1315 files
  webpack://kb-web/./node_modules/ieee754/index.js
  webpack://kb-web/./src/render/components/form/DeflectionModal/index.js
  webpack://kb-web/./node_modules/react-with-styles-interface-css/...
  ...
```

## Impact
Source maps expose:
- Internal application structure and component hierarchy
- API endpoint paths and request patterns
- Business logic that could reveal further vulnerabilities
- Internal comments and developer notes
- Dependency versions (useful for known CVE exploitation)

An attacker can reconstruct the entire frontend application source code, making it significantly easier to find client-side vulnerabilities (DOM XSS, logic flaws, hardcoded secrets).

## Remediation
- Remove `.map` files from production deployment
- Configure the web server to block access to `*.map` files
- Or restrict source map access to authenticated internal users only
