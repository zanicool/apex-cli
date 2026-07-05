#!/usr/bin/env python3
"""
H1 Dupe Checker — Checks HackerOne hacktivity for existing reports.

Usage:
  ./h1check.py <program> "<your finding>"

Examples:
  ./h1check.py shopify "IDOR on orders API"
  ./h1check.py whatnot "GraphQL unauthenticated"
  ./h1check.py uber "XSS in profile page"
"""
import sys, time, re

def get_disclosed_reports(program):
    from selenium import webdriver
    from selenium.webdriver.firefox.options import Options

    opts = Options()
    opts.add_argument('--headless')
    driver = webdriver.Firefox(options=opts)

    url = f"https://hackerone.com/hacktivity/overview?queryString=disclosed%3Atrue%20program%3A{program}"
    driver.get(url)
    time.sleep(8)

    source = driver.page_source
    driver.quit()

    # Extract vuln titles
    keywords = ['xss','sql','ssrf','idor','cors','redirect','injection','bypass',
                'takeover','leak','expos','graphql','rce','csrf','ssti','lfi',
                'upload','race','privilege','auth','token','password','session',
                'misconfigur','information','disclosure','subdomain','bucket',
                'api','endpoint','traversal','smuggling','overflow','open']

    titles = set()
    for match in re.findall(r'>([A-Z][^<]{10,150})<', source):
        m = match.strip()
        if any(kw in m.lower() for kw in keywords):
            titles.add(m)

    for match in re.findall(r'"title":"([^"]{10,150})"', source):
        if any(kw in match.lower() for kw in keywords):
            titles.add(match)

    return sorted(titles)


def check(program, finding):
    print(f"\n🔍 Checking H1 hacktivity for: {program}")
    print(f"   Finding: {finding}\n")

    reports = get_disclosed_reports(program)

    if not reports:
        print(f"   ⚠️  No disclosed reports for '{program}'")
        print(f"   Cannot verify — dupe risk UNKNOWN\n")
        return

    print(f"   📋 {len(reports)} disclosed reports:\n")

    # Match
    words = [w for w in finding.lower().split() if len(w) > 3]
    matches = []
    for title in reports:
        lower = title.lower()
        hits = sum(1 for w in words if w in lower)
        if hits >= 2:
            matches.append(title)

    for t in reports[:25]:
        mark = "  ⚠️ " if t in matches else "     "
        print(f"{mark}{t[:90]}")

    print()
    if matches:
        print(f"   🔴 DUPLICATE — {len(matches)} match(es):")
        for m in matches:
            print(f"      → {m[:90]}")
        print(f"\n   ❌ Don't submit.")
    else:
        print(f"   🟢 No match found in disclosed reports.")
        print(f"   ✅ Submit (but undisclosed dupes still possible).")
    print()


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)
    check(sys.argv[1], " ".join(sys.argv[2:]))
