#!/usr/bin/env python3
"""
H1 Dupe Checker — Scrapes HackerOne hacktivity to check if a finding is already disclosed.

Usage:
  python3 h1_dupecheck.py shopify "IDOR"
  python3 h1_dupecheck.py uber "XSS account takeover"
  python3 h1_dupecheck.py whatnot "GraphQL"
"""
import sys
import re
import time

def scrape_hacktivity(program, search_term=""):
    from selenium import webdriver
    from selenium.webdriver.firefox.options import Options

    opts = Options()
    opts.add_argument('--headless')
    driver = webdriver.Firefox(options=opts)

    # Load hacktivity page with disclosed filter
    url = f"https://hackerone.com/hacktivity/overview?queryString=disclosed%3Atrue%20program%3A{program}"
    driver.get(url)
    time.sleep(8)

    source = driver.page_source

    # Extract vulnerability titles from page
    # Pattern 1: visible text that looks like vuln titles
    visible = re.findall(r'>([A-Z][^<]{10,150})</[^>]*>', source)
    vuln_keywords = ['xss','sql','ssrf','idor','cors','redirect','injection','bypass',
                     'takeover','leak','expos','graphql','rce','csrf','ssti','lfi',
                     'upload','deserialization','race','privilege','auth','token',
                     'password','session','cookie','header','open','misconfigur',
                     'information','disclosure','subdomain','bucket','api','endpoint']
    
    titles = []
    seen = set()
    for v in visible:
        v = v.strip()
        if v in seen or len(v) < 12:
            continue
        if any(kw in v.lower() for kw in vuln_keywords):
            seen.add(v)
            titles.append(v)

    # Pattern 2: JSON embedded data
    json_titles = re.findall(r'"title":"([^"]{10,150})"', source)
    for t in json_titles:
        if t not in seen and any(kw in t.lower() for kw in vuln_keywords):
            seen.add(t)
            titles.append(t)

    driver.quit()
    return titles


def check_duplicate(program, finding_description):
    print(f"\n🔍 Checking H1 hacktivity for: {program}")
    print(f"   Finding: {finding_description}\n")

    titles = scrape_hacktivity(program)

    if not titles:
        print(f"   ⚠️  No disclosed reports found for '{program}'")
        print(f"   This program doesn't disclose reports — cannot check for dupes.")
        print(f"   Dupe risk: UNKNOWN\n")
        return

    print(f"   📋 Found {len(titles)} disclosed reports:\n")

    # Check for matches
    search_words = finding_description.lower().split()
    matches = []
    for title in titles:
        title_lower = title.lower()
        match_count = sum(1 for w in search_words if w in title_lower)
        if match_count >= 2 or any(w in title_lower for w in search_words if len(w) > 4):
            matches.append(title)

    # Show all disclosed titles
    for t in titles[:20]:
        marker = "  ⚠️  " if t in matches else "      "
        print(f"{marker}{t[:90]}")

    print()
    if matches:
        print(f"   🔴 LIKELY DUPLICATE — {len(matches)} similar report(s) found:")
        for m in matches:
            print(f"      → {m[:90]}")
        print(f"\n   💡 Don't submit. This has been found before.")
    else:
        print(f"   🟢 NO MATCH — Your finding doesn't match any disclosed report.")
        print(f"   💡 Looks unique! But undisclosed dupes are still possible.")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: h1_dupecheck.py <program> <finding description>")
        print("Example: h1_dupecheck.py shopify 'IDOR on orders API'")
        sys.exit(1)

    program = sys.argv[1]
    finding = " ".join(sys.argv[2:])
    check_duplicate(program, finding)
