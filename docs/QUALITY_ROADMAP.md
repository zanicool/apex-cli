# Apex CLI — Quality Improvement Roadmap

## Probleem

225 scanners, veel output, weinig bruikbare findings. False positive rate is te hoog voor responsible disclosure.

## Prioriteit 1: Verificatie verbeteren

- **Baseline-vergelijking per scanner** — niet alleen in Phase 4b, maar in elke scanner zelf. Als een response hetzelfde is met/zonder payload → geen finding.
- **Evidence vereist** — geen finding zonder concreet bewijs dat NIET in de baseline zit.
- **Confidence score** — elke finding krijgt confirmed/likely/possible/unconfirmed. Alleen confirmed komt in het rapport.

## Prioriteit 2: WP Plugin scanner uitbreiden

Dit is de meest waardevolle scanner (levert echte CVE's met bewijs):
- Versies extraheren uit `readme.txt` per plugin (`/wp-content/plugins/X/readme.txt`)
- Stable tag vergelijken met WPScan vulnerability database
- Niet alleen `?ver=` in CSS/JS maar ook `Stable tag:` in readme
- Automatisch Patchstack/Wordfence API queryen naast OSV

## Prioriteit 3: Minder scanners, betere kwaliteit

Huidige 225 scanners terugbrengen naar ~50 die echt werken:
- Verwijder scanners die alleen "info" findings produceren zonder actie
- Verwijder scanners die niet verifieerbaar zijn (blind injections zonder OOB)
- Focus op: versie-detectie + CVE lookup, misconfiguratie, exposed panels

## Prioriteit 4: Scan performance

- DNS resolution cachen (nu doet elke scanner eigen DNS lookups)
- Subdomain checks parallel maar met shared DNS cache
- Timeout per scanner (niet alleen per HTTP request)
- `--quick` moet echt snel zijn (<30s)

## Prioriteit 5: ZAP integratie testen

- ZAP installeren in dev environment
- End-to-end test: apex recon → ZAP config → ZAP scan → merged report
- ZAP findings importeren in apex report format
- Authenticated scanning via ZAP (apex detecteert login form, ZAP voert auth uit)

## Prioriteit 6: Rapport voor disclosure

- Markdown disclosure template genereren per confirmed finding
- Inclusief: URL, bewijs-screenshot (via headless Chrome), reproductiestappen
- CVSS score berekenen per finding
- Timeline suggestie (90 dagen standaard)

## Prioriteit 7: Supply chain scanner verbeteren

- Niet alleen subdomains raden, maar DNS records queryen (MX, TXT, CNAME)
- SPF/DKIM/DMARC check (email security)
- Certificate Transparency logs voor subdomain discovery
- Shodan/Censys integratie voor exposed services

## Wat nu wél werkt

- WP plugin versie-detectie + CVE lookup (meest waardevolle feature)
- Security headers check
- Login security (captcha/lockout detectie)
- xmlrpc.php detectie
- Verificatie-fase met baseline vergelijking (elimineert false positives)
- ZAP config generatie (niet getest maar code is correct)

## Conclusie

Focus op kwaliteit boven kwantiteit. 10 scanners die bewezen findings leveren zijn meer waard dan 225 die ruis produceren.
