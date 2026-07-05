#!/usr/bin/env python3
"""Extract JS library versions from a target's scripts."""
import sys, re, urllib.request
target = sys.argv[1] if len(sys.argv) > 1 else ""
if not target: sys.exit("Usage: js-versions.py <url>")

html = urllib.request.urlopen(target).read().decode(errors='ignore')
js_files = re.findall(r'src="([^"]*\.js[^"]*)"', html)

patterns = {
    "jQuery": r'jquery[.-](\d+\.\d+\.\d+)',
    "Angular": r'angular[.-](\d+\.\d+\.\d+)',
    "React": r'react[.-](\d+\.\d+\.\d+)',
    "Vue": r'vue[.-](\d+\.\d+\.\d+)',
    "Bootstrap": r'bootstrap[.-](\d+\.\d+\.\d+)',
    "lodash": r'lodash[.-](\d+\.\d+\.\d+)',
    "moment": r'moment[.-](\d+\.\d+\.\d+)',
}

found = {}
for js in js_files[:20]:
    for lib, pat in patterns.items():
        m = re.search(pat, js, re.IGNORECASE)
        if m: found[lib] = m.group(1)

# Also check inline version strings
for lib, pat in patterns.items():
    m = re.search(pat, html)
    if m and lib not in found: found[lib] = m.group(1)

for lib, ver in found.items():
    print(f"{lib} {ver}")
