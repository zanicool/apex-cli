#!/usr/bin/env python3
"""Apex CLI benchmark — auto-tunes workers, timeouts, and AI model based on hardware."""

import json, os, time, subprocess, shutil, sys
from pathlib import Path

CONFIG_FILE = Path.home() / ".apex_benchmark.json"
APEX_DIR = Path(__file__).parent


def benchmark_cpu():
    """Measure CPU speed via simple computation."""
    start = time.time()
    x = sum(i * i for i in range(1_000_000))
    return round(time.time() - start, 3)


def benchmark_network():
    """Measure network latency to common targets."""
    import urllib.request
    times = []
    for url in ["https://1.1.1.1", "https://8.8.8.8"]:
        try:
            start = time.time()
            urllib.request.urlopen(url, timeout=3)
            times.append(time.time() - start)
        except Exception:
            times.append(1.0)
    return round(sum(times) / len(times), 3)


def benchmark_gpu():
    """Detect GPU and VRAM."""
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=name,memory.total,memory.free",
             "--format=csv,noheader,nounits"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            lines = result.stdout.strip().splitlines()
            gpus = []
            for line in lines:
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 3:
                    gpus.append({
                        "name": parts[0],
                        "total_mb": int(parts[1]),
                        "free_mb": int(parts[2]),
                    })
            return gpus
    except Exception:
        pass
    return []


def benchmark_ollama():
    """Find best available Ollama model and measure inference speed."""
    try:
        import requests
        r = requests.get("http://localhost:11434/api/tags", timeout=3)
        if r.status_code != 200:
            return None, None
        models = [m["name"] for m in r.json().get("models", [])]
        if not models:
            return None, None

        # Prefer fast small models
        preferred = [
            "llama3.2:latest", "llama3.2:3b", "llama3.1:8b",
            "mistral:7b", "dolphin-mistral:7b", "gemma:2b",
        ]
        best_model = next((m for m in preferred if m in models), models[0])

        # Benchmark inference speed
        start = time.time()
        r2 = requests.post("http://localhost:11434/api/generate", json={
            "model": best_model,
            "prompt": "Reply with exactly: BENCHMARK_OK",
            "stream": False,
            "options": {"num_predict": 10, "temperature": 0}
        }, timeout=30)
        elapsed = time.time() - start
        return best_model, round(elapsed, 2)
    except Exception:
        return None, None


def benchmark_tools():
    """Check which tools are available and their versions."""
    tools = {}
    for tool in ["subfinder", "httpx", "nuclei", "ffuf", "nmap", "sqlmap",
                 "amass", "assetfinder", "interactsh-client"]:
        path = shutil.which(tool)
        if not path:
            # Check ~/go/bin
            go_path = Path.home() / "go" / "bin" / tool
            path = str(go_path) if go_path.exists() else None
        tools[tool] = bool(path)
    return tools


def run_benchmark(force=False):
    """Run full benchmark and save results. Returns config dict."""
    # Check if benchmark already done and hardware hasn't changed
    if not force and CONFIG_FILE.exists():
        try:
            config = json.loads(CONFIG_FILE.read_text())
            # Re-benchmark if GPU changed or config is old (>7 days)
            age = time.time() - config.get("timestamp", 0)
            if age < 7 * 86400:
                return config
        except Exception:
            pass

    print("\n\033[1;31m☠ APEX CLI — First Run Benchmark\033[0m")
    print("\033[2mDetecting hardware and auto-tuning settings...\033[0m\n")

    config = {"timestamp": time.time()}

    # CPU
    print("  [1/5] CPU benchmark...", end="", flush=True)
    cpu_time = benchmark_cpu()
    cpu_score = "fast" if cpu_time < 0.1 else "medium" if cpu_time < 0.3 else "slow"
    config["cpu"] = {"time": cpu_time, "score": cpu_score}
    print(f" {cpu_time}s ({cpu_score})")

    # GPU
    print("  [2/5] GPU detection...", end="", flush=True)
    gpus = benchmark_gpu()
    config["gpu"] = gpus
    if gpus:
        vram = gpus[0]["total_mb"]
        print(f" {gpus[0]['name']} ({vram}MB VRAM)")
    else:
        print(" no GPU detected")

    # Network
    print("  [3/5] Network latency...", end="", flush=True)
    net_time = benchmark_network()
    net_score = "fast" if net_time < 0.2 else "medium" if net_time < 0.5 else "slow"
    config["network"] = {"latency": net_time, "score": net_score}
    print(f" {net_time}s ({net_score})")

    # Tools
    print("  [4/5] Tool detection...", end="", flush=True)
    tools = benchmark_tools()
    config["tools"] = tools
    found = sum(tools.values())
    print(f" {found}/{len(tools)} tools found")

    # AI/Ollama
    print("  [5/5] AI model benchmark...", end="", flush=True)
    model, inference_time = benchmark_ollama()
    config["ai"] = {"model": model, "inference_time": inference_time}
    if model:
        print(f" {model} ({inference_time}s/response)")
    else:
        print(" Ollama not running")

    # --- Auto-tune settings ---
    settings = {}

    # Workers: based on CPU + network
    if cpu_score == "fast" and net_score == "fast":
        settings["workers"] = 12
    elif cpu_score == "slow" or net_score == "slow":
        settings["workers"] = 4
    else:
        settings["workers"] = 8

    # Timeout: based on network
    settings["timeout"] = 5 if net_score == "fast" else 8 if net_score == "medium" else 12

    # AI model: based on VRAM
    vram_mb = gpus[0]["total_mb"] if gpus else 0
    if model:
        settings["ai_model"] = model  # Use benchmarked best model
    elif vram_mb >= 8000:
        settings["ai_model"] = "llama3.1:8b"
    elif vram_mb >= 4000:
        settings["ai_model"] = "llama3.2:latest"
    else:
        settings["ai_model"] = "llama3.2:latest"  # Smallest

    # AI workers: 3 parallel if fast, 1 if slow
    if inference_time and inference_time < 5:
        settings["ai_workers"] = 3
    elif inference_time and inference_time < 15:
        settings["ai_workers"] = 2
    else:
        settings["ai_workers"] = 1

    # Rate limit: be gentle on slow networks
    settings["rate_delay"] = 0.0 if net_score == "fast" else 0.05

    config["settings"] = settings

    # Save
    CONFIG_FILE.write_text(json.dumps(config, indent=2))

    print(f"""
\033[1;32m✓ Auto-tuned settings:\033[0m
  Workers:     {settings['workers']} parallel threads
  Timeout:     {settings['timeout']}s per request
  AI model:    {settings['ai_model']}
  AI workers:  {settings['ai_workers']} parallel queries
  Rate delay:  {settings['rate_delay']}s between requests
""")

    return config


def get_settings():
    """Get current settings, running benchmark if needed."""
    return run_benchmark(force=False).get("settings", {})


def apply_settings(settings):
    """Apply benchmark settings to scanners module."""
    try:
        sys.path.insert(0, str(APEX_DIR))
        import scanners
        if settings.get("rate_delay", 0) > 0:
            scanners.set_rate_limit(settings["rate_delay"])
        if settings.get("timeout"):
            scanners._TIMEOUT = settings["timeout"]
    except Exception:
        pass


if __name__ == "__main__":
    force = "--force" in sys.argv
    config = run_benchmark(force=force)
    if "--json" in sys.argv:
        print(json.dumps(config, indent=2))
