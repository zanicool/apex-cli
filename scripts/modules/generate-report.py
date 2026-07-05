#!/usr/bin/env python3
"""Generate HackerOne report from scan findings."""
import json, sys

if len(sys.argv) < 2:
    sys.exit("Usage: generate-report.py <report.json>")

data = json.load(open(sys.argv[1]))
findings = data.get("findings", [])

for f in findings:
    if f.get("severity") not in ("critical", "high"): continue
    print(f"""## Title
{f.get('type')} on {f.get('url','')}

## Weakness
CWE-200

## Severity
{f.get('severity','medium').title()}

## Steps To Reproduce
1. Navigate to: `{f.get('url','')}`
2. {f.get('evidence','Observe the vulnerable behavior')}

## PoC
```
curl -sk "{f.get('url','')}"
```

## Impact
{f.get('type')} allows an attacker to compromise the security of the application.

---
""")
