# Security Inventory Runbook

## Dagelijkse Monitoring

### 1. CMS Inventory Check
```bash
# Scan alle bedrijfsdomeinen
./build/apex-cli company.com --output ./reports/$(date +%Y%m%d)

# Check outdated CMS
grep "OUTDATED" ./reports/$(date +%Y%m%d)/cms_inventory.csv
```

**Actie bij outdated**:
- Medium severity: Plan update binnen 2 weken
- High severity: Update binnen 48 uur
- Critical: Immediate patching

### 2. OSINT Leak Monitoring
```bash
# Run OSINT scan
./build/apex-cli company.com --osint --output ./reports/$(date +%Y%m%d)

# Check critical leaks
grep "critical" ./reports/$(date +%Y%m%d)/osint_leaks.csv
```

**Actie bij leaks**:
1. **GitHub secrets**: Revoke API keys immediately
2. **HaveIBeenPwned**: Force password reset + enable 2FA
3. **Pastebin**: Contact legal, request takedown

## Wekelijkse Review

### Employee Exposure Audit
```bash
# Analyseer employee data
cat ./reports/*/osint_employees.csv | sort | uniq > employees_week.csv

# Check nieuwe exposures
diff employees_last_week.csv employees_week.csv
```

**Actie**:
- Train employees over LinkedIn privacy
- Review exposed email addresses
- Check voor phishing risico's

### Tech Stack Analysis
```bash
# Consolideer tech stack
cat ./reports/*/osint_techstack.csv | cut -d',' -f2 | sort | uniq -c | sort -rn
```

**Actie**:
- Update asset inventory
- Check EOL software
- Plan migrations

## Maandelijkse Rapportage

### Executive Dashboard
```bash
# Generate summary
./scripts/generate_summary.sh $(date +%Y-%m)
```

**Metrics**:
- Aantal outdated CMS systemen
- Aantal data breaches
- Aantal exposed employees
- Trend analysis (↑↓)

### Update CMS Versions
```bash
# Update latest versions in code
vim src/cms_detector.cpp
# Update fingerprints array met nieuwe versies
make build
```

## Incident Response

### Critical Leak Detected
```
1. Verify leak (check source)
2. Revoke credentials immediately
3. Notify security team
4. Force password reset
5. Enable 2FA
6. Monitor for abuse
7. Document incident
```

### Data Breach Notification
```
1. Check HIBP for details
2. Identify affected users
3. Notify users binnen 72u (GDPR)
4. Force password reset
5. Monitor account activity
6. Update security policies
```

## Automation

### Cron Jobs
```bash
# Daily CMS scan (02:00)
0 2 * * * /opt/apex-cli/build/apex-cli company.com --output /var/reports/$(date +\%Y\%m\%d) 2>&1 | logger -t apex-cms

# Daily OSINT scan (03:00)
0 3 * * * /opt/apex-cli/build/apex-cli company.com --osint --output /var/reports/$(date +\%Y\%m\%d) 2>&1 | logger -t apex-osint

# Weekly summary (Monday 08:00)
0 8 * * 1 /opt/apex-cli/scripts/weekly_summary.sh | mail -s "Security Inventory" security@company.com
```

### Alerting
```bash
# Alert on critical findings
if grep -q "critical" osint_leaks.csv; then
    echo "CRITICAL LEAK DETECTED" | mail -s "URGENT: Security Alert" security@company.com
fi

# Alert on outdated CMS
OUTDATED=$(grep -c "OUTDATED" cms_inventory.csv)
if [ $OUTDATED -gt 5 ]; then
    echo "$OUTDATED outdated CMS detected" | mail -s "CMS Update Required" devops@company.com
fi
```

## Troubleshooting

### Rate Limiting
```bash
# Use proxy rotation
./build/apex-cli company.com --proxy http://proxy1.local:8080
./build/apex-cli company.com --proxy http://proxy2.local:8080

# Add delays
./build/apex-cli company.com --rate 2  # 2 sec tussen requests
```

### False Positives
```bash
# Skip specific scanners
./build/apex-cli company.com --skip "CMS Detection"

# Whitelist known false positives
echo "example.com,WordPress,5.0.0" >> whitelist.csv
```

### API Failures
```bash
# Check HIBP status
curl -I https://haveibeenpwned.com/api/v3/

# Fallback to local breach DB
./build/apex-cli company.com --osint --no-hibp
```

## Compliance

### GDPR
- Employee data: Alleen bedrijfsdomeinen scannen
- Data retention: Max 90 dagen
- Right to erasure: Script voor data deletion

### Logging
```bash
# Audit trail
tail -f /var/log/apex.log

# Retention: 1 jaar
find /var/reports -mtime +365 -delete
```

## Contacts

- **Security Team**: security@company.com
- **DevOps**: devops@company.com  
- **Legal**: legal@company.com
- **On-call**: +31-6-12345678
