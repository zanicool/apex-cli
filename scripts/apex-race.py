#!/usr/bin/env python3
"""
Apex Race Engine — HTTP/2 parallel request blaster for race condition exploitation.

Sends N identical requests simultaneously using HTTP/2 multiplexing (single TCP connection)
to trigger TOCTOU (Time-of-Check-Time-of-Use) vulnerabilities.

This is equivalent to Turbo Intruder's "single packet attack" technique.

Usage:
    apex-race <url> --method POST --body '{"coupon":"FREE50"}' --count 20
    apex-race <url> --method GET --count 50 --header "Authorization: Bearer TOKEN"

What it finds:
    - Double-spend on payments/withdrawals
    - Coupon/promo code reuse
    - Multiple free trial activations
    - Duplicate votes/likes/follows
    - Inventory oversell
    - Race on account creation
    - Referral credit duplication
"""

import sys
import json
import time
import asyncio
import argparse
from dataclasses import dataclass

try:
    import httpx
except ImportError:
    print("Install httpx: pip install httpx[http2]")
    sys.exit(1)


@dataclass
class RaceResult:
    total_sent: int = 0
    successful: int = 0
    unique_responses: int = 0
    status_codes: dict = None
    response_bodies: list = None
    duration_ms: float = 0
    race_detected: bool = False
    evidence: str = ""

    def __post_init__(self):
        if self.status_codes is None:
            self.status_codes = {}
        if self.response_bodies is None:
            self.response_bodies = []


async def blast_requests(
    url: str,
    method: str = "GET",
    body: str = None,
    headers: dict = None,
    count: int = 20,
    use_http2: bool = True,
) -> RaceResult:
    """Send N requests simultaneously via HTTP/2 multiplexing."""
    result = RaceResult()
    
    if headers is None:
        headers = {}
    
    headers.setdefault("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")

    async with httpx.AsyncClient(
        http2=use_http2,
        verify=False,
        timeout=30.0,
        limits=httpx.Limits(max_connections=1, max_keepalive_connections=1),
    ) as client:
        # Build all requests
        requests = []
        for _ in range(count):
            if method.upper() == "POST":
                requests.append(
                    client.post(url, content=body, headers=headers)
                )
            elif method.upper() == "PUT":
                requests.append(
                    client.put(url, content=body, headers=headers)
                )
            elif method.upper() == "DELETE":
                requests.append(client.delete(url, headers=headers))
            else:
                requests.append(client.get(url, headers=headers))

        # Fire all at once
        start = time.time()
        responses = await asyncio.gather(*requests, return_exceptions=True)
        result.duration_ms = (time.time() - start) * 1000

    # Analyze responses
    result.total_sent = count
    bodies = []
    
    for resp in responses:
        if isinstance(resp, Exception):
            continue
        result.successful += 1
        code = resp.status_code
        result.status_codes[code] = result.status_codes.get(code, 0) + 1
        bodies.append(resp.text[:500])

    # Detect race condition
    result.response_bodies = bodies
    unique_bodies = set(bodies)
    result.unique_responses = len(unique_bodies)

    # Race detected if:
    # 1. All requests succeed (200) when only one should
    # 2. Multiple "success" responses for a one-time action
    success_count = result.status_codes.get(200, 0) + result.status_codes.get(201, 0)
    
    if success_count > 1:
        # Check if responses indicate multiple successful operations
        success_indicators = ["success", "true", "created", "applied", "redeemed", "approved"]
        confirmed_successes = 0
        for body in bodies:
            if any(ind in body.lower() for ind in success_indicators):
                confirmed_successes += 1
        
        if confirmed_successes > 1:
            result.race_detected = True
            result.evidence = (
                f"{confirmed_successes}/{count} requests succeeded. "
                f"Expected: 1 success, {count-1} failures. "
                f"This confirms a race condition — the operation is not atomic."
            )
    
    # Also detect by status code pattern
    # If we expect 1 success + N-1 failures but get all successes
    if success_count >= count * 0.8:
        # Check if it's not just an idempotent GET
        if method.upper() != "GET":
            result.race_detected = True
            result.evidence = (
                f"{success_count}/{count} requests returned success status. "
                f"For a state-changing {method} request, this indicates "
                f"missing atomicity/locking."
            )

    return result


def print_result(result: RaceResult, url: str, method: str):
    """Pretty print the race result."""
    print(f"\n{'='*60}")
    print(f"  APEX RACE ENGINE RESULTS")
    print(f"{'='*60}")
    print(f"  Target: {url}")
    print(f"  Method: {method}")
    print(f"  Requests sent: {result.total_sent}")
    print(f"  Successful: {result.successful}")
    print(f"  Duration: {result.duration_ms:.0f}ms")
    print(f"  Unique responses: {result.unique_responses}")
    print(f"  Status codes: {result.status_codes}")
    print()
    
    if result.race_detected:
        print(f"  🚨 RACE CONDITION DETECTED!")
        print(f"  Evidence: {result.evidence}")
        print()
        print(f"  Impact: The operation can be performed multiple times")
        print(f"  simultaneously, bypassing single-use restrictions.")
    else:
        print(f"  ✅ No race condition detected.")
        print(f"  (Try with authentication or different endpoints)")
    
    print(f"{'='*60}\n")


async def main():
    parser = argparse.ArgumentParser(description="Apex Race Condition Engine")
    parser.add_argument("url", help="Target URL")
    parser.add_argument("--method", "-m", default="GET", help="HTTP method (GET/POST/PUT/DELETE)")
    parser.add_argument("--body", "-b", help="Request body")
    parser.add_argument("--count", "-c", type=int, default=20, help="Number of parallel requests")
    parser.add_argument("--header", "-H", action="append", help="Extra headers (key:value)")
    parser.add_argument("--no-http2", action="store_true", help="Disable HTTP/2")
    parser.add_argument("--json-output", "-j", action="store_true", help="JSON output")
    
    args = parser.parse_args()
    
    headers = {}
    if args.header:
        for h in args.header:
            key, val = h.split(":", 1)
            headers[key.strip()] = val.strip()
    
    if args.body and not headers.get("Content-Type"):
        headers["Content-Type"] = "application/json"

    print(f"\n[*] Apex Race Engine — sending {args.count} parallel requests...")
    print(f"[*] Target: {args.url}")
    print(f"[*] Method: {args.method}")
    if args.body:
        print(f"[*] Body: {args.body[:100]}")
    
    result = await blast_requests(
        url=args.url,
        method=args.method,
        body=args.body,
        headers=headers,
        count=args.count,
        use_http2=not args.no_http2,
    )
    
    if args.json_output:
        print(json.dumps({
            "target": args.url,
            "method": args.method,
            "total_sent": result.total_sent,
            "successful": result.successful,
            "duration_ms": result.duration_ms,
            "status_codes": result.status_codes,
            "unique_responses": result.unique_responses,
            "race_detected": result.race_detected,
            "evidence": result.evidence,
        }, indent=2))
    else:
        print_result(result, args.url, args.method)


if __name__ == "__main__":
    asyncio.run(main())
