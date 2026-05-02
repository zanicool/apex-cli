#!/usr/bin/env python3
"""Apex OOB callback server — catches blind SSRF/XSS/SQLi/CMDi."""
import http.server, threading, json, time
from urllib.parse import urlparse, parse_qs

callbacks = {}
lock = threading.Lock()

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/poll":
            uid = parse_qs(parsed.query).get("uid", [""])[0]
            with lock: data = callbacks.get(uid)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"hit": bool(data), "data": data}).encode())
        elif parsed.path == "/list":
            with lock: data = dict(callbacks)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data).encode())
        else:
            uid = parsed.path.strip("/").split("/")[0][:32]
            if uid:
                with lock:
                    callbacks[uid] = {"time": time.time(), "path": self.path, "ip": self.client_address[0]}
                print(f"[HIT] uid={uid} from={self.client_address[0]} path={self.path}", flush=True)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
    do_POST = do_GET
    def log_message(self, *a): pass

PORT = 9877
print(f"[*] Apex OOB server: http://10.0.0.72:{PORT}/<uid>", flush=True)
http.server.HTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
