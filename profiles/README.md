# ZAP Scan Profiles

Targeted scan profiles for OWASP ZAP Automation Framework.

## Usage

```bash
# Run a profile
zap.sh -cmd -autorun profiles/wordpress/scan.yaml -config target.url=https://example.com

# Or via Docker
docker run --rm -v $(pwd)/profiles:/profiles ghcr.io/zaproxy/zaproxy:stable \
  zap.sh -cmd -autorun /profiles/wordpress/scan.yaml
```

## Structure

```
profiles/
├── README.md
├── <technology>/
│   ├── scan.yaml        — ZAP automation framework plan
│   ├── urls.txt         — seed URLs / paths to crawl
│   └── policy.yaml      — custom scan policy (active scan rules)
```

## Available Profiles

| Profile | Target | Focus |
|---------|--------|-------|
| wordpress | WordPress sites | WP-specific vulns, plugins, themes, xmlrpc, REST API |
