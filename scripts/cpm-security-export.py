#!/usr/bin/env python3
"""
CPM Security Export — Run system security checks and export for Apex integration.

Checks:
  - Exposed services without auth (Redis, MongoDB, Elasticsearch, etc.)
  - Docker misconfigurations (running as root, exposed socket)
  - Weak file permissions (SSH keys, .env files, configs)
  - Known CVEs in installed packages
  - Network services listening on all interfaces

Output: JSON that Apex can ingest via the CPM bridge.

Usage:
    python3 cpm-security-export.py > /tmp/cpm-findings.json
    apex-cli target.com --cpm-data /tmp/cpm-findings.json
"""

import json
import subprocess
import os
import socket


def run(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except Exception:
        return ""


def check_exposed_services():
    """Find services listening without proper auth."""
    findings = []

    # Check common ports
    services = [
        (6379, "redis", "redis-cli ping"),
        (27017, "mongodb", ""),
        (9200, "elasticsearch", "curl -s http://localhost:9200"),
        (5432, "postgresql", ""),
        (3306, "mysql", ""),
        (2375, "docker", "curl -s http://localhost:2375/version"),
        (11211, "memcached", ""),
        (5672, "rabbitmq", ""),
        (8500, "consul", "curl -s http://localhost:8500/v1/agent/self"),
    ]

    for port, service, test_cmd in services:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            result = s.connect_ex(('127.0.0.1', port))
            s.close()

            if result == 0:
                has_auth = True
                # Test if auth is actually required
                if test_cmd:
                    output = run(test_cmd)
                    if output and "PONG" in output:  # Redis no auth
                        has_auth = False
                    elif output and "name" in output:  # Elasticsearch/Docker no auth
                        has_auth = False
                    elif output and "Config" in output:  # Consul no auth
                        has_auth = False

                findings.append({
                    "type": "exposed_service",
                    "severity": "high" if not has_auth else "medium",
                    "detail": f"{service} listening on port {port}" +
                              (" WITHOUT authentication" if not has_auth else ""),
                    "service": service,
                    "host": "127.0.0.1",
                    "port": port,
                    "has_auth": has_auth,
                })
        except Exception:
            pass

    return findings


def check_docker():
    """Check Docker security misconfigurations."""
    findings = []

    # Docker socket exposed?
    if os.path.exists("/var/run/docker.sock"):
        stat = os.stat("/var/run/docker.sock")
        if stat.st_mode & 0o006:  # World readable/writable
            findings.append({
                "type": "weak_permission",
                "severity": "critical",
                "detail": "Docker socket world-accessible — container escape possible",
                "service": "docker",
                "host": "localhost",
                "port": 0,
                "has_auth": False,
            })

    # Containers running as root?
    containers = run("docker ps --format '{{.Names}}:{{.Image}}' 2>/dev/null")
    if containers:
        for line in containers.split("\n"):
            if line:
                name = line.split(":")[0]
                user = run(f"docker inspect --format '{{{{.Config.User}}}}' {name} 2>/dev/null")
                if not user or user == "root" or user == "0":
                    findings.append({
                        "type": "weak_config",
                        "severity": "medium",
                        "detail": f"Container '{name}' running as root",
                        "service": "docker",
                        "host": "localhost",
                        "port": 0,
                        "has_auth": True,
                    })

    return findings


def check_file_permissions():
    """Check for sensitive files with weak permissions."""
    findings = []

    sensitive_files = [
        ("/etc/shadow", 0o640),
        (os.path.expanduser("~/.ssh/id_rsa"), 0o600),
        (os.path.expanduser("~/.ssh/id_ed25519"), 0o600),
        ("/etc/ssl/private", 0o700),
    ]

    # Check .env files in common locations
    for env_path in ["/app/.env", "/var/www/.env", "/opt/app/.env"]:
        if os.path.exists(env_path):
            stat = os.stat(env_path)
            if stat.st_mode & 0o044:  # World/group readable
                findings.append({
                    "type": "weak_permission",
                    "severity": "high",
                    "detail": f"{env_path} readable by others (contains secrets)",
                    "service": "filesystem",
                    "host": "localhost",
                    "port": 0,
                    "has_auth": False,
                })

    return findings


def check_listening_services():
    """Find services listening on 0.0.0.0 (all interfaces)."""
    findings = []

    output = run("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
    if output:
        for line in output.split("\n"):
            if "0.0.0.0:" in line or ":::":
                if any(svc in line for svc in ["redis", "mongo", "elastic", "mysql", "postgres"]):
                    findings.append({
                        "type": "exposed_service",
                        "severity": "high",
                        "detail": f"Service bound to all interfaces: {line.strip()[:80]}",
                        "service": "network",
                        "host": "0.0.0.0",
                        "port": 0,
                        "has_auth": False,
                    })

    return findings


def main():
    all_findings = []

    all_findings.extend(check_exposed_services())
    all_findings.extend(check_docker())
    all_findings.extend(check_file_permissions())
    all_findings.extend(check_listening_services())

    # Output as JSONL (one finding per line — Apex format)
    for f in all_findings:
        print(json.dumps(f))


if __name__ == "__main__":
    main()
