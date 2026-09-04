#!/usr/bin/env python3
"""Precision harness for apex-cli.

Starts the local vulnerable target, runs apex-cli against it, then scores the
findings against the KNOWN set of planted bugs. Prints detection rate and
false-positive rate — the two numbers that decide whether the scanner is
"pro" (high signal) or a toy (high noise).

Owns the target process lifecycle so it works regardless of shell backgrounding
quirks. Usage:
    python3 tests/precision_harness.py [--confidence N] [--port P]
"""
import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
TARGET = os.path.join(HERE, "local_vuln_target.py")
APEX = os.path.join(ROOT, "build", "apex-cli")

# Ground truth: vuln TYPE -> the endpoint path where it is really planted.
# A finding is a TRUE positive only if its type is planted AND its url matches
# the planted endpoint. Everything else scored as noise.
PLANTED = {
    "SQLi": "/users",
    "XSS": ("/search", "/template"),   # both reflect
    "CMDi": "/ping",
    "SSTI": "/template",
    "LFI": "/file",
    "Open Redirect": "/redirect",
    "SSRF": "/fetch",
}
# Types we count as "core" true-positive classes for the detection rate.
CORE = ["SQLi", "XSS", "CMDi", "SSTI", "LFI", "Open Redirect", "SSRF"]


def wait_up(port, timeout=8):
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), 0.3):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def matches_planted(vtype, url):
    # Normalize type family (e.g. "SSRF Variant" -> "SSRF").
    fam = None
    for k in PLANTED:
        if vtype == k or vtype.startswith(k + " ") or k in vtype:
            fam = k
            break
    if fam is None:
        return None  # not a planted class at all -> not scored as TP/FP-core
    planted_paths = PLANTED[fam]
    if isinstance(planted_paths, str):
        planted_paths = (planted_paths,)
    hit = any(p in url for p in planted_paths)
    return (fam, hit)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--confidence", type=int, default=2)
    ap.add_argument("--port", type=int, default=8091)
    ap.add_argument("--timeout", type=int, default=200)
    args = ap.parse_args()

    outdir = "/tmp/apex_precision"
    proc = subprocess.Popen([sys.executable, TARGET, str(args.port)],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            preexec_fn=os.setsid)
    try:
        if not wait_up(args.port):
            print("FAIL: target did not come up", file=sys.stderr)
            return 2
        cmd = [APEX, f"http://127.0.0.1:{args.port}", "--threads", "20",
               "--output", outdir]
        if args.confidence:
            cmd += ["--confidence", str(args.confidence)]
        subprocess.run(cmd, timeout=args.timeout,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    finally:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            pass

    report = os.path.join(outdir, "report.json")
    if not os.path.exists(report):
        print("FAIL: no report produced", file=sys.stderr)
        return 2
    findings = json.load(open(report)).get("findings", [])

    tp_families = set()
    core_tp = 0
    core_fp = 0
    scored = 0
    for f in findings:
        r = matches_planted(f.get("type", ""), f.get("url", ""))
        if r is None:
            continue
        fam, hit = r
        scored += 1
        if hit:
            core_tp += 1
            tp_families.add(fam)
        else:
            core_fp += 1

    detected = len(tp_families)
    detection_rate = detected / len(CORE)
    fp_rate = core_fp / scored if scored else 0.0

    print(f"total findings (confidence>={args.confidence}): {len(findings)}")
    print(f"core vuln classes detected: {detected}/{len(CORE)} "
          f"({detection_rate*100:.0f}%)  -> {sorted(tp_families)}")
    print(f"core true positives: {core_tp}")
    print(f"core false positives (wrong endpoint): {core_fp}")
    print(f"core false-positive rate: {fp_rate*100:.0f}%")
    # Machine-readable line for CI.
    print(f"METRICS detection={detection_rate:.2f} fp_rate={fp_rate:.2f} "
          f"total={len(findings)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
