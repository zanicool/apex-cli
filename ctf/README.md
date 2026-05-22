# 🏴‍☠️ Hack the Kristelijn

A father-son CTF platform. Papa builds challenges, Zani breaks them.

## Quick Start

```bash
# Start everything
docker compose -f ctf/docker-compose.yml up -d

# Scoreboard
open http://localhost:8000

# Challenges run on ports 5001-5012
```

## Challenges

| # | Port | Level | Name | Technique |
|---|------|-------|------|-----------|
| 1 | 5001 | 🟢 | Hidden Flag | View source |
| 2 | 5002 | 🟢 | Robot Secrets | robots.txt |
| 3 | 5003 | 🟢 | Header Hunt | HTTP headers |
| 4 | 5004 | 🟡 | Login Bypass | SQL injection |
| 5 | 5005 | 🟡 | File Reader | Path traversal |
| 6 | 5006 | 🟡 | Git History | .git exposure |
| 7 | 5007 | 🔵 | Cookie Thief | XSS |
| 8 | 5008 | 🔵 | Internal Access | SSRF |
| 9 | 5009 | 🔵 | Token Forge | JWT bypass |
| 10 | 5010 | 🟣 | Other Users | IDOR |
| 11 | 5011 | 🟣 | Template RCE | SSTI → file read |
| 12 | 5012 | 🟣 | Chain Attack | Multi-step |
| 13 | 5013 | 🔴 | Headless | Info leak → SSRF → RCE (5 steps) |
| 14 | 5014 | 🔴 | Sau | Proxy → traversal → cmd injection |
| 15 | 5015 | 🔴 | Clicker | Race condition → JWT forge → privesc |
| 16 | 5016 | 🔴 | Codify | Sandbox escape → cred leak → LFI |
| 17 | 5017 | 🔴 | MegaCorp BOSS | IDOR → reset → WAF bypass → RCE |

## Rules

1. All flags look like: `FLAG{something_here}`
2. Use any tool you want (apex-cli, curl, browser, Burp)
3. Document what you try (even failures!)
4. Ask for hints if stuck (costs points)
5. No looking at Dockerfiles (that's cheating 😄)

## Tools Allowed

```bash
# Scanner
./build/apex-cli http://localhost:5004 --smart

# Manual
curl -v http://localhost:5003
curl http://localhost:5005/view?file=../../../flag.txt

# Browser dev tools (F12)
# Burp Suite Community Edition
```

## Scoring

- 🟢 Level 1: 10-15 points each
- 🟡 Level 2: 20-25 points each
- 🔵 Level 3: 50 points each
- 🟣 Level 4: 100-150 points each
- 🔴 Level 5: 200-300 points each (HTB Medium/Hard equivalent)

**Total possible: 1,535 points**

Bonus points for:
- Finding unintended solutions
- Writing a clear explanation of HOW
- Suggesting a fix
- Solving Level 5 without hints
- Using apex-cli to find the vuln automatically

## For Papa: Adding New Challenges

```bash
# Create a new challenge
mkdir ctf/challenges/lvl2-newchallenge
# Add Dockerfile + app.py
# Add to docker-compose.yml
# Register flag in CTFd scoreboard
```

## The Chess Game

Papa's job: make challenges harder over time.
Zani's job: find creative ways to break them.

The real learning happens in the conversation:
- "How did you find that?"
- "What else could you try?"
- "How would you fix this?"
