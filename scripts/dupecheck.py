#!/usr/bin/env python3
"""
Apex Dupe Checker — Check if a finding is likely already reported on HackerOne.

Sources:
1. H1 public hacktivity (disclosed reports)
2. Google dorking for disclosed reports
3. Local database of our own submissions
4. Common vulnerability patterns that are always duped

Usage:
  python3 dupecheck.py --program whatnot --type "GraphQL" --target "api.dev.whatnot.com"
  python3 dupecheck.py --program koho --type "CORS" --target "referral.koho.ca"
"""
import argparse
import json
import os
import sys
import urllib.request
import urllib.parse
import re
from pathlib import Path

DB_PATH = Path.home() / ".apex-cache" / "dupecheck.json"

# Vuln types that are ALWAYS heavily reported (high dupe risk)
ALWAYS_DUPED = {
    "missing headers": 0.95,
    "clickjacking": 0.95,
    "cookie security": 0.90,
    "information disclosure": 0.85,
    "open redirect": 0.80,
    "cors": 0.70,
    "source map": 0.85,
    "graphql introspection": 0.90,
    "dev environment": 0.85,
    "staging exposed": 0.85,
    "subdomain takeover": 0.60,
    "xss": 0.50,
    "sqli": 0.30,
    "ssrf": 0.35,
    "idor": 0.40,
    "rce": 0.15,
    "account takeover": 0.20,
}

# Endpoints that everyone finds
COMMON_TARGETS = [
    ".env", ".git", "graphql", "admin", "swagger", "actuator",
    "debug", "phpinfo", "server-status", "wp-admin", "config",
    "dev.", "stage.", "test.", "qa.",
]


def check_dupe_risk(program, vuln_type, target, detail=""):
    """Returns (risk_score 0-1, reasons[])"""
    reasons = []
    score = 0.0

    # Check 1: Is this vuln type commonly duped?
    vt_lower = vuln_type.lower()
    for pattern, risk in ALWAYS_DUPED.items():
        if pattern in vt_lower:
            score = max(score, risk)
            reasons.append(f"'{pattern}' findings are commonly reported (base risk: {risk:.0%})")
            break

    # Check 2: Is this a common target/endpoint?
    target_lower = target.lower()
    for common in COMMON_TARGETS:
        if common in target_lower:
            score = min(1.0, score + 0.15)
            reasons.append(f"Target contains '{common}' — commonly scanned endpoint")
            break

    # Check 3: Is this a dev/staging environment?
    if any(env in target_lower for env in ["dev.", "stage.", "test.", "qa.", "sandbox"]):
        score = min(1.0, score + 0.20)
        reasons.append("Non-production environment — many hunters check these first")

    # Check 4: Program report volume (if known)
    program_stats = get_program_stats(program)
    if program_stats:
        reports_90d = program_stats.get("reports_90d", 0)
        if reports_90d > 1000:
            score = min(1.0, score + 0.15)
            reasons.append(f"High-volume program ({reports_90d} reports/90d) — competition is fierce")
        elif reports_90d > 500:
            score = min(1.0, score + 0.10)
            reasons.append(f"Active program ({reports_90d} reports/90d)")

    # Check 5: Check our local submission history
    if check_local_db(program, vuln_type, target):
        score = 1.0
        reasons.append("Already submitted by us!")

    # Check 6: Google for disclosed reports
    google_hits = check_google(program, vuln_type, target)
    if google_hits:
        score = min(1.0, score + 0.25)
        reasons.append(f"Found {google_hits} related disclosed reports via search")

    return score, reasons


def get_program_stats(program):
    """Known program stats (hardcoded for speed)"""
    stats = {
        "whatnot": {"reports_90d": 1658, "avg_bounty": 750},
        "coinmate": {"reports_90d": 311, "avg_bounty": 50},
        "koho": {"reports_90d": 200, "avg_bounty": 500},
        "hilton": {"reports_90d": 500, "avg_bounty": 1000},
    }
    return stats.get(program.lower())


def check_local_db(program, vuln_type, target):
    """Check if we already reported this"""
    if not DB_PATH.exists():
        return False
    try:
        db = json.loads(DB_PATH.read_text())
        for entry in db.get("submitted", []):
            if (entry.get("program", "").lower() == program.lower() and
                entry.get("target", "").lower() == target.lower()):
                return True
    except:
        pass
    return False


def check_google(program, vuln_type, target):
    """Search for existing disclosed reports"""
    query = f"site:hackerone.com {program} {vuln_type}"
    encoded = urllib.parse.quote(query)
    try:
        req = urllib.request.Request(
            f"https://www.google.com/search?q={encoded}&num=5",
            headers={"User-Agent": "Mozilla/5.0"}
        )
        resp = urllib.request.urlopen(req, timeout=10)
        body = resp.read().decode(errors="ignore")
        # Count hackerone.com/reports/ links
        hits = len(re.findall(r"hackerone\.com/reports/\d+", body))
        return hits
    except:
        return 0


def record_submission(program, vuln_type, target):
    """Record that we submitted this"""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    db = {"submitted": []}
    if DB_PATH.exists():
        try:
            db = json.loads(DB_PATH.read_text())
        except:
            pass
    db["submitted"].append({
        "program": program,
        "vuln_type": vuln_type,
        "target": target,
        "date": str(__import__("datetime").datetime.now())
    })
    DB_PATH.write_text(json.dumps(db, indent=2))


def main():
    parser = argparse.ArgumentParser(description="Check duplicate risk before submitting to H1")
    parser.add_argument("--program", "-p", required=True, help="H1 program handle")
    parser.add_argument("--type", "-t", required=True, help="Vulnerability type")
    parser.add_argument("--target", "-T", required=True, help="Target URL/domain")
    parser.add_argument("--record", action="store_true", help="Record this as submitted")
    args = parser.parse_args()

    if args.record:
        record_submission(args.program, args.type, args.target)
        print("✓ Recorded submission")
        return

    score, reasons = check_dupe_risk(args.program, args.type, args.target)

    # Display result
    if score >= 0.75:
        icon = "🔴"
        verdict = "HIGH DUPE RISK — probably already reported"
    elif score >= 0.50:
        icon = "🟡"
        verdict = "MEDIUM DUPE RISK — check hacktivity first"
    elif score >= 0.25:
        icon = "🟢"
        verdict = "LOW DUPE RISK — likely unique, submit"
    else:
        icon = "✅"
        verdict = "VERY LOW RISK — submit immediately"

    print(f"\n{icon} Dupe Risk: {score:.0%} — {verdict}\n")
    for r in reasons:
        print(f"  • {r}")
    print()

    if score >= 0.75:
        print("💡 Recommendation: Skip this, find something more unique.")
    elif score >= 0.50:
        print("💡 Recommendation: Submit but expect possible duplicate.")
    else:
        print("💡 Recommendation: Submit! Good chance it's unique.")


if __name__ == "__main__":
    main()
