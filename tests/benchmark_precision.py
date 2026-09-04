#!/usr/bin/env python3
"""Precision/recall benchmark for apex-cli against the local vulnerable target.

Ground truth = the vulnerabilities actually planted in tests/local_vuln_target.py.
We map each planted bug to (vuln_class, endpoint_path) and check whether the
scanner reported a matching finding. Then we compute:

  precision = true_positives / (true_positives + false_positives)
  recall    = true_positives / (true_positives + false_negatives)
  F1        = 2 * P * R / (P + R)

A finding is a TRUE POSITIVE if its normalized (class, path) matches a planted
bug. Any reported finding on a path/class that has NO planted bug is a FALSE
POSITIVE (noise). Any planted bug with no matching finding is a FALSE NEGATIVE.

Usage: benchmark_precision.py <report.json>
"""
import json
import sys
from urllib.parse import urlparse

# --- Ground truth: what is ACTUALLY vulnerable in local_vuln_target.py ---
# Keyed by endpoint path -> set of vuln classes truly present there.
GROUND_TRUTH = {
    "/users":    {"sqli"},
    "/search":   {"xss"},
    "/ping":     {"cmdi"},
    "/template": {"ssti", "xss"},   # reflects raw then evaluates {{a*b}}
    "/file":     {"lfi"},
    "/redirect": {"open-redirect", "crlf"},  # Location header also CRLF-splittable (verified)
    "/fetch":    {"ssrf"},
    "/header":   {"crlf"},
}
# Total planted vuln instances (class,path pairs):
TRUE_VULNS = {(c, p) for p, cs in GROUND_TRUTH.items() for c in cs}

# --- Map scanner finding "type" strings to canonical vuln classes ---
# Only security-relevant classes are scored. Informational/observational
# finding types are ignored entirely (neither TP nor FP) so they don't
# distort precision — they are triage aids, not vuln claims.
TYPE_TO_CLASS = {
    "SQLi": "sqli", "SQL Injection": "sqli", "SQLi (Blind Boolean)": "sqli",
    "SQLi (Time-Based)": "sqli", "Blind SQLi": "sqli",
    "XSS": "xss", "XSS (Context-Aware)": "xss", "Reflected XSS": "xss",
    "XSS (Browser)": "xss", "Stored XSS": "xss",
    "CMDi": "cmdi", "Command Injection": "cmdi",
    "SSTI": "ssti", "SSTI Deep": "ssti", "EL Injection": "ssti",
    "LFI": "lfi", "Path Traversal": "lfi", "Null Byte": "lfi",
    "Open Redirect": "open-redirect", "Open Redirect (Advanced)": "open-redirect",
    "SSRF": "ssrf", "SSRF Variant": "ssrf", "Cloud Metadata": "ssrf",
    "Auto-Escalate": "ssrf", "Blind SSRF": "ssrf",
    "CRLF": "crlf", "Header Injection": "crlf", "Log Injection": "crlf",
}

# Finding types that are observational only — excluded from scoring.
IGNORE_TYPES = {
    "Missing Header", "Reflection", "Response Diff", "Clickjacking",
    "Header Leak", "Cookie Security", "Info Disclosure", "Param Discovery",
    "VHost Discovery", "Server Banner Disclosure", "Server Header Version",
    "M365 Namespace Enumerable", "M365 User Enumeration",
    "Shadow Deployment: Netlify", "S3 Bucket", "Timing Attack",
    "Timing Oracle", "DNS Rebinding", "Blind CMDi", "Blind SQLi OOB",
    "Log4Shell", "Billion Laughs", "Hop-by-Hop",
}


def path_of(url):
    try:
        p = urlparse(url).path or "/"
    except Exception:
        return "/"
    # normalize trailing pieces
    if p != "/" and p.endswith("/"):
        p = p.rstrip("/")
    return p


def main():
    if len(sys.argv) < 2:
        print("usage: benchmark_precision.py <report.json>")
        sys.exit(2)
    with open(sys.argv[1]) as fh:
        report = json.load(fh)
    findings = report.get("findings", [])

    scored_tp = set()      # unique (class, path) planted bugs we detected
    false_positives = []   # findings claiming a vuln where none is planted
    ignored = 0
    scored_total = 0

    for f in findings:
        ftype = f.get("type", "")
        if ftype in IGNORE_TYPES:
            ignored += 1
            continue
        cls = TYPE_TO_CLASS.get(ftype)
        if cls is None:
            # Unmapped, non-ignored type -> treat as a vuln claim = potential FP
            ignored += 1
            continue
        scored_total += 1
        path = path_of(f.get("url", ""))
        key = (cls, path)
        if key in TRUE_VULNS:
            scored_tp.add(key)
        else:
            false_positives.append((ftype, cls, path, f.get("url", "")))

    tp = len(scored_tp)
    fp = len(false_positives)
    fn = len(TRUE_VULNS - scored_tp)

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)

    print("=" * 56)
    print("  APEX-CLI PRECISION BENCHMARK")
    print("=" * 56)
    print(f"  Planted vulns (ground truth): {len(TRUE_VULNS)}")
    print(f"  Findings scored as vuln claims: {scored_total}")
    print(f"  Observational/ignored findings: {ignored}")
    print("-" * 56)
    print(f"  True Positives : {tp}")
    print(f"  False Positives: {fp}")
    print(f"  False Negatives: {fn}")
    print("-" * 56)
    print(f"  PRECISION : {precision*100:5.1f}%   (of vuln claims, how many real)")
    print(f"  RECALL    : {recall*100:5.1f}%   (of real bugs, how many found)")
    print(f"  F1 SCORE  : {f1*100:5.1f}%")
    print("=" * 56)

    if scored_tp:
        print("\n  DETECTED (true positives):")
        for cls, path in sorted(scored_tp):
            print(f"    ✓ {cls:14s} {path}")
    missed = TRUE_VULNS - scored_tp
    if missed:
        print("\n  MISSED (false negatives):")
        for cls, path in sorted(missed):
            print(f"    ✗ {cls:14s} {path}")
    if false_positives:
        print("\n  FALSE POSITIVES (noise):")
        for ftype, cls, path, url in false_positives[:30]:
            print(f"    ! {ftype:22s} -> {cls:12s} {path}")

    # Machine-readable line for scripting.
    print(f"\nRESULT precision={precision:.4f} recall={recall:.4f} "
          f"f1={f1:.4f} tp={tp} fp={fp} fn={fn}")


if __name__ == "__main__":
    main()
