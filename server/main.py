#!/usr/bin/env python3
"""Apex Scanner API v2 — Production server with auth, rate limiting, usage tracking, Stripe ready."""

import asyncio
import hashlib
import json
import os
import time
import uuid
from datetime import datetime
from pathlib import Path

import stripe
from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel

app = FastAPI(title="Apex Scanner API", version="2.0.0", docs_url=None, redoc_url=None, openapi_url=None)


# --- Security Headers Middleware (#15) ---

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=()"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        if "server" in response.headers:
            del response.headers["server"]
        return response


app.add_middleware(SecurityHeadersMiddleware)

# Config
APEX_BINARY = os.getenv("APEX_BINARY", "/home/roz/apex-api/apex-cli")
DATA_DIR = Path(os.getenv("DATA_DIR", "/home/roz/apex-api/data"))
DATA_DIR.mkdir(exist_ok=True)
KEYS_FILE = Path("/home/roz/apex-api/server/keys.json")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
MAX_CONCURRENT = 3
MAX_SCANS_PER_DAY = 50
SCAN_TIMEOUT = 600

# Security
bearer_scheme = HTTPBearer()

# State
scans: dict = {}
running_count: dict = {}
daily_usage: dict = {}  # client -> {date: count}


# --- Key Management ---

def load_keys() -> dict:
    if KEYS_FILE.exists():
        return json.loads(KEYS_FILE.read_text())
    return {}


def save_keys(keys: dict):
    KEYS_FILE.write_text(json.dumps(keys, indent=2))


def hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def verify_key(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme)) -> dict:
    key = credentials.credentials
    h = hash_key(key)
    keys = load_keys()
    if h not in keys:
        raise HTTPException(403, {"error": "Invalid API key"})
    client = keys[h]
    if not client.get("active", False):
        raise HTTPException(403, {"error": "Subscription expired. Renew at https://republicofzani.com/apex"})
    # Check expiry
    if client.get("expires_at") and time.time() > client["expires_at"]:
        keys[h]["active"] = False
        save_keys(keys)
        raise HTTPException(403, {"error": "Subscription expired. Renew at https://republicofzani.com/apex"})
    return client


def check_rate_limit(client_name: str):
    today = datetime.utcnow().strftime("%Y-%m-%d")
    key = f"{client_name}:{today}"
    count = daily_usage.get(key, 0)
    if count >= MAX_SCANS_PER_DAY:
        raise HTTPException(429, {"error": f"Daily limit reached ({MAX_SCANS_PER_DAY} scans/day)"})
    daily_usage[key] = count + 1


# --- Models ---

class ScanRequest(BaseModel):
    target: str
    options: list[str] = []


class ScanResult(BaseModel):
    scan_id: str
    status: str
    target: str
    started_at: float
    finished_at: float | None = None
    duration: float | None = None
    finding_count: int = 0
    findings: list | None = None
    error: str | None = None


# --- Scan Logic ---

ALLOWED_OPTIONS = {"--deep", "--threads", "--timeout", "--no-oob", "--browser"}
BLOCKED_CHARS = set(";|&$`(){}[]!#")


def validate_target(target: str) -> str:
    target = target.strip()
    if not target or len(target) > 200:
        raise HTTPException(400, {"error": "Invalid target"})
    if any(c in target for c in BLOCKED_CHARS):
        raise HTTPException(400, {"error": "Invalid characters in target"})
    return target


def sanitize_options(options: list[str]) -> list[str]:
    safe = []
    for opt in options:
        parts = opt.split()
        if parts and parts[0] in ALLOWED_OPTIONS:
            # Only allow numeric values for flags with args
            if len(parts) == 2 and parts[1].isdigit() and int(parts[1]) <= 50:
                safe.extend(parts)
            elif len(parts) == 1:
                safe.append(parts[0])
    return safe


async def run_scan(scan_id: str, target: str, options: list[str], client_name: str):
    # Limit CPU: nice 19 (lowest priority) + max 2 threads forced
    if "--threads" not in " ".join(options):
        options += ["--threads", "2"]
    cmd = ["nice", "-n", "19", APEX_BINARY, target] + options + ["--json", "--no-color"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=SCAN_TIMEOUT)

        findings = []
        for line in stdout.decode(errors="replace").splitlines():
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        scans[scan_id]["status"] = "done"
        scans[scan_id]["findings"] = findings
        scans[scan_id]["finding_count"] = len(findings)
        scans[scan_id]["finished_at"] = time.time()
        scans[scan_id]["duration"] = scans[scan_id]["finished_at"] - scans[scan_id]["started_at"]

        # Save to disk
        out = DATA_DIR / f"{scan_id}.json"
        out.write_text(json.dumps(scans[scan_id], indent=2, default=str))

    except asyncio.TimeoutError:
        scans[scan_id]["status"] = "timeout"
        scans[scan_id]["error"] = "Scan timed out (10 min max)"
    except Exception as e:
        scans[scan_id]["status"] = "error"
        scans[scan_id]["error"] = str(e)
    finally:
        running_count[client_name] = max(0, running_count.get(client_name, 1) - 1)


# --- Routes ---

@app.post("/scan")
async def start_scan(req: ScanRequest, bg: BackgroundTasks, client: dict = Depends(verify_key)):
    client_name = client["client"]

    check_rate_limit(client_name)

    if running_count.get(client_name, 0) >= MAX_CONCURRENT:
        raise HTTPException(429, {"error": f"Max {MAX_CONCURRENT} concurrent scans. Wait for one to finish."})

    target = validate_target(req.target)
    options = sanitize_options(req.options)

    scan_id = uuid.uuid4().hex[:8]
    scans[scan_id] = {
        "scan_id": scan_id,
        "status": "running",
        "target": target,
        "client": client_name,
        "started_at": time.time(),
        "finished_at": None,
        "duration": None,
        "finding_count": 0,
        "findings": None,
        "error": None,
    }
    running_count[client_name] = running_count.get(client_name, 0) + 1
    bg.add_task(run_scan, scan_id, target, options, client_name)
    return {"scan_id": scan_id, "status": "running"}


@app.get("/scan/{scan_id}")
async def get_scan(scan_id: str, client: dict = Depends(verify_key)):
    if scan_id not in scans or scans[scan_id]["client"] != client["client"]:
        raise HTTPException(404, {"error": "Scan not found"})
    s = scans[scan_id]
    return ScanResult(**{k: v for k, v in s.items() if k != "client"})


@app.get("/scans")
async def list_scans(client: dict = Depends(verify_key)):
    return [
        {"scan_id": s["scan_id"], "status": s["status"], "target": s["target"], "finding_count": s["finding_count"]}
        for s in scans.values()
        if s["client"] == client["client"]
    ]


@app.get("/usage")
async def get_usage(client: dict = Depends(verify_key)):
    today = datetime.utcnow().strftime("%Y-%m-%d")
    key = f"{client['client']}:{today}"
    return {
        "scans_today": daily_usage.get(key, 0),
        "daily_limit": MAX_SCANS_PER_DAY,
        "concurrent_running": running_count.get(client["client"], 0),
        "concurrent_limit": MAX_CONCURRENT,
    }


# --- Stripe Webhook (payment automation) ---

@app.post("/webhook/stripe")
async def stripe_webhook(request: Request):
    """Handle Stripe subscription events. Auto-activate/deactivate keys."""
    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(500, {"error": "Webhook secret not configured"})

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        raise HTTPException(400, {"error": "Invalid payload"})
    except stripe.error.SignatureVerificationError:
        raise HTTPException(400, {"error": "Invalid signature"})

    event_type = event["type"]

    if event_type == "checkout.session.completed":
        # New subscriber — activate key
        email = event["data"]["object"].get("customer_email", "")
        # Key provisioning handled manually for now
        pass

    elif event_type in ("customer.subscription.deleted", "invoice.payment_failed"):
        # Deactivate client
        customer_email = event["data"]["object"].get("customer_email", "")
        keys = load_keys()
        for h, info in keys.items():
            if info.get("email") == customer_email:
                keys[h]["active"] = False
                save_keys(keys)
                break

    return {"received": True}


# --- Health ---

@app.get("/health")
async def health():
    return {"status": "ok", "version": "2.0.0"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9000, server_header=False)
