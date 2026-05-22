# 🎓 Learning Path — Van CTF naar Bug Bounty

## Week 1-2: Fundamentals (PortSwigger Academy)

Gratis, interactief, industrie-standaard. Doe deze labs in volgorde:

1. **SQL Injection** → https://portswigger.net/web-security/sql-injection
2. **XSS** → https://portswigger.net/web-security/cross-site-scripting
3. **SSRF** → https://portswigger.net/web-security/ssrf
4. **Path Traversal** → https://portswigger.net/web-security/file-path-traversal
5. **Authentication** → https://portswigger.net/web-security/authentication
6. **Access Control (IDOR)** → https://portswigger.net/web-security/access-control
7. **JWT Attacks** → https://portswigger.net/web-security/jwt
8. **SSTI** → https://portswigger.net/web-security/server-side-template-injection
9. **Race Conditions** → https://portswigger.net/web-security/race-conditions

Na elke lab: probeer dezelfde techniek op onze CTF challenges.

## Week 3-4: Bug Bounty Training (Hacker101)

Gratis CTF van HackerOne. Punten → uitnodigingen voor private programma's.

- https://www.hacker101.com
- Doe de CTF challenges (makkelijk → moeilijk)
- Na 26 punten: uitnodiging voor private HackerOne programma's

## Week 5+: Eerste Echte Targets

### Setup
```bash
# HackerOne account
open https://hackerone.com/sign_up

# Kies een programma met brede scope
# Goed voor beginners: Shopify, GitLab, U.S. Dept of Defense
```

### Workflow
```bash
# 1. Recon
./build/apex-cli target.com --pipeline --program <naam>

# 2. Handmatig verifiëren (PortSwigger technieken)
# 3. Rapporteren via HackerOne
```

## Cheatsheets (altijd open houden)

| Resource | Wat | Link |
|----------|-----|------|
| HackTricks | Cheatsheet per vuln type | https://book.hacktricks.wiki |
| PayloadsAllTheThings | Payload lijsten | https://github.com/swisskyrepo/PayloadsAllTheThings |
| OWASP Testing Guide | Systematische methodology | https://owasp.org/www-project-web-security-testing-guide |
| CyberChef | Encoding/decoding tool | https://gchq.github.io/CyberChef |

## Gratis Boeken & Guides

| Titel | Focus | Link |
|-------|-------|------|
| OWASP Web Security Testing Guide v4.2 | Methodology | https://owasp.org/www-project-web-security-testing-guide |
| PortSwigger Research Blog | Cutting-edge technieken | https://portswigger.net/research |
| HackerOne Hacktivity | Echte rapporten lezen | https://hackerone.com/hacktivity |
| PentesterLab (free tier) | Progressive challenges | https://pentesterlab.com |

## Betaalde Boeken (als je serieus wilt)

1. **Bug Bounty Bootcamp** (Vickie Li) — stap-voor-stap methodology
2. **Real World Bug Hunting** (Peter Yaworski) — echte bounty reports uitgelegd
3. **The Web Application Hacker's Handbook 2** — de bijbel

## YouTube Channels

| Channel | Stijl |
|---------|-------|
| John Hammond | CTF walkthroughs, beginner-friendly |
| IppSec | HTB walkthroughs (exact wat je nodig hebt) |
| NahamSec | Bug bounty tips, live hacking |
| LiveOverflow | Diepgaande technische uitleg |
| STÖK | Bug bounty lifestyle + tips |

## Het Pad

```
Onze CTF (lvl 1-4)     → basis technieken leren
PortSwigger Academy     → technieken verdiepen met labs
Onze CTF (lvl 5)       → chaining leren
Hacker101 CTF           → punten → private programma's
HackTheBox              → realistische machines
Eerste bounty target    → apex-cli --pipeline
💰 Eerste bounty        → 3-6 maanden
```

## Tip van Papa

Het verschil tussen een scriptkiddie en een hacker:
- Scriptkiddie: draait een tool, copy-paste payload, hoopt op geluk
- Hacker: **begrijpt** waarom iets werkt, kan improviseren, documenteert alles

Lees de PortSwigger labs niet alleen — **begrijp** waarom de payload werkt.
Schrijf op wat je probeert, ook als het faalt. Dat is je logboek.
