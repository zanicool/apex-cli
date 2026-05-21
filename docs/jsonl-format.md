# JSONL Recon Format

## cms_recon.jsonl
```jsonl
{"timestamp":"2026-05-21T17:20:00Z","url":"https://example.com","cms":"WordPress","version":"6.2.0","latest":"6.5.3","outdated":true}
{"timestamp":"2026-05-21T17:20:05Z","url":"https://shop.example.com","cms":"Shopify","version":"Unknown","latest":"N/A","outdated":false}
{"timestamp":"2026-05-21T17:20:10Z","url":"https://blog.example.com","cms":"Ghost","version":"5.80.0","latest":"5.82.0","outdated":true}
```

## osint_recon.jsonl
```jsonl
{"timestamp":"2026-05-21T17:25:00Z","type":"leak","source":"HaveIBeenPwned","leak_type":"email","value":"user@example.com","breach":"LinkedIn","date":"2021-06-22","severity":"high"}
{"timestamp":"2026-05-21T17:25:05Z","type":"leak","source":"GitHub","leak_type":"api_key","value":"ghp_xxxxxxxxxxxx...","breach":"company/secrets","date":"","severity":"critical"}
{"timestamp":"2026-05-21T17:25:10Z","type":"employee","name":"John Doe","email":"john@example.com","role":"Senior Developer","linkedin":"https://linkedin.com/in/johndoe"}
{"timestamp":"2026-05-21T17:25:15Z","type":"techstack","source":"job_posting","technology":"AWS","version":"","url":"https://linkedin.com/jobs/123"}
{"timestamp":"2026-05-21T17:25:20Z","type":"techstack","source":"certificate","technology":"subdomain","version":"api.example.com","url":"crt.sh"}
```

## vuln_recon.jsonl
```jsonl
{"timestamp":"2026-05-21T17:30:00Z","type":"SQLi","severity":"critical","url":"https://example.com/search?q=test","detail":"SQL error in response: mysql_fetch","param":"q","payload":"' OR '1'='1","evidence":"mysql_fetch_array()"}
{"timestamp":"2026-05-21T17:30:05Z","type":"XSS","severity":"high","url":"https://example.com/comment","detail":"Reflected XSS","param":"text","payload":"<script>alert(1)</script>","evidence":"<script>alert(1)</script>"}
{"timestamp":"2026-05-21T17:30:10Z","type":"CMS Detection","severity":"medium","url":"https://example.com","detail":"Detected: WordPress v6.2.0 (OUTDATED - Latest: 6.5.3)","param":"","payload":"","evidence":"WordPress|6.2.0|6.5.3"}
```

## Query Examples

### Find all outdated CMS
```bash
jq 'select(.outdated == true)' cms_recon.jsonl
```

### Critical leaks in last 24h
```bash
jq 'select(.severity == "critical" and (.timestamp | fromdateiso8601) > (now - 86400))' osint_recon.jsonl
```

### Employee exposure count
```bash
jq 'select(.type == "employee")' osint_recon.jsonl | wc -l
```

### Tech stack summary
```bash
jq -r 'select(.type == "techstack") | .technology' osint_recon.jsonl | sort | uniq -c
```

### Vulnerability timeline
```bash
jq -r '"\(.timestamp) | \(.type) | \(.severity) | \(.url)"' vuln_recon.jsonl | tail -50
```

### Export to CSV
```bash
jq -r '[.timestamp, .cms, .version, .latest, .outdated] | @csv' cms_recon.jsonl > cms_history.csv
```

### Aggregate by date
```bash
jq -r '.timestamp[:10]' vuln_recon.jsonl | sort | uniq -c
```

### Filter by domain
```bash
jq 'select(.url | contains("example.com"))' vuln_recon.jsonl
```

## Benefits

✅ **Append-only**: Volledige history, geen data loss  
✅ **Queryable**: jq, grep, awk, SQL (via sqlite-utils)  
✅ **Timestamped**: Trend analysis mogelijk  
✅ **Structured**: Machine-readable, easy parsing  
✅ **Compact**: Efficient storage, fast queries  

## Integration

### Import to PostgreSQL
```bash
cat cms_recon.jsonl | jq -c '.' | psql -c "COPY cms_history FROM STDIN WITH (FORMAT csv, QUOTE e'\x01', DELIMITER e'\x02')"
```

### Import to Elasticsearch
```bash
cat vuln_recon.jsonl | curl -X POST "localhost:9200/vulns/_bulk" -H 'Content-Type: application/x-ndjson' --data-binary @-
```

### Grafana Dashboard
```sql
SELECT 
  date_trunc('day', timestamp) as day,
  severity,
  count(*) 
FROM vuln_recon 
GROUP BY day, severity 
ORDER BY day DESC;
```

## Retention Policy

```bash
# Keep last 90 days
find . -name "*_recon.jsonl" -mtime +90 -exec gzip {} \;

# Archive to S3
aws s3 sync . s3://recon-archive/ --exclude "*" --include "*_recon.jsonl.gz"
```
