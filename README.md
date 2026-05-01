# Apex CLI v2.0

Automated pen-test orchestrator that chains recon, probing, fuzzing, and vulnerability scanning into a single command.

## Features

- **Subdomain enumeration** — Subfinder, Amass, Assetfinder (auto-skips missing tools)
- **Live host probing** — httpx (preferred) or Nmap fallback
- **Directory fuzzing** — ffuf with auto-detected wordlists
- **Vulnerability scanning** — Nuclei with severity filtering
- **SQL injection testing** — SQLMap with crawl + forms
- **Reports** — Terminal (Rich), JSON, and HTML (dark-themed)
- **Smart defaults** — Auto-discovers tools in PATH, validates targets, deduplicates results
- **Dry-run mode** — Preview every command without sending packets

## Requirements

Python 3.10+ and at least one scanning tool installed.

```bash
pip install -r requirements.txt
```

### Supported tools

| Tool | Purpose | Required? |
|------|---------|-----------|
| subfinder | Subdomain enumeration | No |
| amass | Subdomain enumeration (deep mode) | No |
| assetfinder | Subdomain enumeration (deep mode) | No |
| httpx | Live host probing | Recommended |
| nmap | Port scanning (httpx fallback) | No |
| ffuf | Directory fuzzing | No |
| nuclei | Vulnerability scanning | Recommended |
| sqlmap | SQL injection testing | No |

Check what's available:
```bash
apex-cli --tools
```

## Usage

```bash
# Basic scan
apex-cli example.com

# Deep scan with HTML report
apex-cli example.com --deep --report html json terminal

# Preview commands without executing
apex-cli example.com --dry-run

# Interactive — prompts for target
apex-cli
```

### Options

| Flag | Description |
|------|-------------|
| `--dry-run` | Preview commands without executing |
| `--deep` | More tools, higher intensity, wider port range |
| `--report FORMAT` | Output formats: `terminal` `json` `html` (multiple allowed) |
| `--tools` | Show installed tools and exit |

## Output

Each scan creates a timestamped directory (`scan_example.com_20250501_134500/`) containing:
- `subdomains.txt` — Deduplicated subdomain list
- `web_targets.txt` — Live web services
- `nuclei.json` — Vulnerability findings (JSONL)
- `report.json` — Full scan data
- `report.html` — Visual report (if `--report html`)
- Individual tool logs

## Install

```bash
git clone <repo-url> && cd apex-cli
pip install -r requirements.txt

# Make globally available
sudo ln -sf "$(pwd)/apex.py" /usr/local/bin/apex-cli
chmod +x apex.py
```
