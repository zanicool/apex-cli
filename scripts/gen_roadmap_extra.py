#!/usr/bin/env python3
"""Add more categories to roadmap-500.md to reach 315+ total."""

OUTPUT = "/home/zani/git/apex-cli/docs/roadmap-500.md"

# Read existing content
with open(OUTPUT) as f:
    existing = f.read()

# Count existing checks
import re
last_num = max(int(m.group(1)) for m in re.finditer(r'^(\d+)\.', existing, re.MULTILINE))
print(f"Existing checks end at: {last_num}")

extra_categories = []

def add(name, checks):
    extra_categories.append((name, checks))

# Batch 1: More reconnaissance/OSINT
add("Subdomain Enumeration Advanced (12)", [
    "Subdomain enumeration via DNS brute force technique",
    "Subdomain enumeration via certificate transparency",
    "Subdomain enumeration via search engine scraping",
    "Subdomain enumeration via virtual host discovery",
    "Subdomain enumeration via zone transfer attempt",
    "Subdomain enumeration via favicon hash correlation",
    "Subdomain enumeration via ASN IP reverse lookup",
    "Subdomain enumeration via content similarity analysis",
    "Subdomain enumeration via JavaScript source parsing",
    "Subdomain enumeration via SPF record analysis",
    "Subdomain enumeration via crossdomain.xml analysis",
    "Subdomain enumeration via CSP header analysis",
])

add("Network Service Discovery (12)", [
    "Network service discovery via TCP SYN scanning",
    "Network service discovery via UDP port scanning",
    "Network service discovery via ARP scan technique",
    "Network service discovery via ICMP echo mapping",
    "Network service discovery via mDNS/Bonjour query",
    "Network service discovery via SSDP UPnP probing",
    "Network service discovery via LLMNR/NBT-NS query",
    "Network service discovery via WS-Discovery probe",
    "Network service discovery via SNMP broadcast scan",
    "Network service discovery via Zeroconf enumeration",
    "Network service discovery via passive traffic analysis",
    "Network service discovery via IPv6 multicast ping",
])

add("Cloud Asset Discovery (12)", [
    "Cloud asset discovery via S3 bucket enumeration",
    "Cloud asset discovery via Azure blob container scan",
    "Cloud asset discovery via GCS bucket enumeration",
    "Cloud asset discovery via cloud IP range scanning",
    "Cloud asset discovery via lambda URL enumeration",
    "Cloud asset discovery via CloudFront distribution scan",
    "Cloud asset discovery via API Gateway endpoint scan",
    "Cloud asset discovery via container registry scan",
    "Cloud asset discovery via serverless function scan",
    "Cloud asset discovery via cloud database endpoint scan",
    "Cloud asset discovery via CDN origin identification",
    "Cloud asset discovery via cloud storage signed URL leak",
])

add("JavaScript Analysis Intelligence (12)", [
    "JavaScript source map exposure exploitation",
    "JavaScript API endpoint extraction technique",
    "JavaScript secret token extraction from bundles",
    "JavaScript hidden admin route discovery method",
    "JavaScript WebSocket endpoint extraction technique",
    "JavaScript GraphQL schema extraction method",
    "JavaScript OAuth configuration extraction",
    "JavaScript feature flag configuration exposure",
    "JavaScript environment variable extraction",
    "JavaScript internal API documentation discovery",
    "JavaScript deprecated endpoint discovery method",
    "JavaScript debug function exposure detection",
])

add("Wireless Security Testing (12)", [
    "WiFi WPA2 handshake capture exploitation",
    "WiFi evil twin access point exploitation",
    "WiFi deauthentication attack for DoS technique",
    "WiFi PMKID hash capture exploitation method",
    "WiFi WPS PIN brute force exploitation",
    "Bluetooth low energy GATT exploitation",
    "Bluetooth classic pairing exploitation technique",
    "ZigBee network key extraction exploitation",
    "Z-Wave network infiltration exploitation method",
    "NFC relay attack exploitation technique",
    "RFID cloning exploitation technique method",
    "WiFi enterprise certificate manipulation attack",
])

add("IoT Device Security (12)", [
    "IoT device firmware extraction exploitation",
    "IoT device hardcoded credential discovery",
    "IoT device UART/JTAG debug interface exploitation",
    "IoT device update mechanism manipulation",
    "IoT device web interface exploitation technique",
    "IoT device MQTT broker unauthorized access",
    "IoT device CoAP endpoint exploitation method",
    "IoT device UPnP exploitation technique",
    "IoT device Telnet service exploitation method",
    "IoT device API key extraction technique",
    "IoT device cloud backend exploitation method",
    "IoT device BLE characteristic manipulation",
])

add("Active Directory Exploitation (12)", [
    "Active Directory Kerberoasting exploitation",
    "Active Directory AS-REP roasting technique",
    "Active Directory password spraying exploitation",
    "Active Directory DCSync exploitation method",
    "Active Directory Golden Ticket exploitation",
    "Active Directory Silver Ticket exploitation",
    "Active Directory delegation exploitation technique",
    "Active Directory NTLM relay exploitation method",
    "Active Directory GPO abuse exploitation technique",
    "Active Directory certificate service exploitation",
    "Active Directory trust relationship exploitation",
    "Active Directory LAPS exploitation technique",
])

add("Windows Exploitation Techniques (12)", [
    "Windows privilege escalation via service misconfiguration",
    "Windows privilege escalation via unquoted path",
    "Windows privilege escalation via token impersonation",
    "Windows privilege escalation via DLL hijacking",
    "Windows privilege escalation via registry exploitation",
    "Windows privilege escalation via scheduled task",
    "Windows lateral movement via WMI exploitation",
    "Windows lateral movement via PsExec technique",
    "Windows lateral movement via WinRM exploitation",
    "Windows persistence via startup registry technique",
    "Windows persistence via service installation method",
    "Windows credential extraction via LSASS dump",
])

add("Linux Exploitation Techniques (12)", [
    "Linux privilege escalation via SUID binary exploitation",
    "Linux privilege escalation via cron job manipulation",
    "Linux privilege escalation via sudo misconfiguration",
    "Linux privilege escalation via capability exploitation",
    "Linux privilege escalation via kernel exploit technique",
    "Linux privilege escalation via path injection method",
    "Linux privilege escalation via NFS misconfiguration",
    "Linux privilege escalation via docker group abuse",
    "Linux privilege escalation via writable service file",
    "Linux persistence via SSH authorized key injection",
    "Linux persistence via cron job installation method",
    "Linux persistence via shared library injection",
])

add("Email Security Testing (12)", [
    "Email SPF record misconfiguration detection",
    "Email DKIM configuration weakness detection",
    "Email DMARC policy enforcement testing method",
    "Email header injection exploitation technique",
    "Email spoofing via subdomain misconfiguration",
    "Email relay testing for open relay detection",
    "Email attachment execution exploitation test",
    "Email HTML rendering exploitation technique",
    "Email tracking pixel detection method",
    "Email URL rewriting bypass exploitation",
    "Email gateway bypass techniques detection",
    "Email encryption enforcement testing method",
])

print(f"Added {len(extra_categories)} categories in batch 1")

add("Web Application Firewall Evasion (12)", [
    "WAF evasion via Unicode encoding manipulation",
    "WAF evasion via double URL encoding technique",
    "WAF evasion via chunked request body technique",
    "WAF evasion via multipart content type confusion",
    "WAF evasion via HTTP parameter pollution method",
    "WAF evasion via case variation exploitation",
    "WAF evasion via comment insertion technique",
    "WAF evasion via whitespace manipulation method",
    "WAF evasion via alternate encoding technique",
    "WAF evasion via payload fragmentation method",
    "WAF evasion via header manipulation technique",
    "WAF evasion via protocol-level confusion method",
])

add("Content Security Policy Bypass (12)", [
    "CSP bypass via unsafe-inline exploitation",
    "CSP bypass via JSONP callback exploitation",
    "CSP bypass via base-uri manipulation technique",
    "CSP bypass via angular sandbox escape method",
    "CSP bypass via script-src wildcard exploitation",
    "CSP bypass via object-src exploitation technique",
    "CSP bypass via data: URI exploitation method",
    "CSP bypass via style injection technique",
    "CSP bypass via nonce reuse exploitation method",
    "CSP bypass via CDN hosted file exploitation",
    "CSP bypass via subdomain script inclusion",
    "CSP bypass via report-uri exploitation technique",
])

add("Clickjacking Advanced Techniques (12)", [
    "Clickjacking via transparent overlay technique",
    "Clickjacking via cursor manipulation method",
    "Clickjacking via drag-and-drop exploitation",
    "Clickjacking via touch event exploitation",
    "Clickjacking via double-click exploitation method",
    "Clickjacking via scroll manipulation technique",
    "Clickjacking via focus manipulation method",
    "Clickjacking via permission prompt exploitation",
    "Clickjacking via fullscreen API exploitation",
    "Clickjacking via frame-ancestors bypass method",
    "Clickjacking via sandbox attribute exploitation",
    "Clickjacking via popup window manipulation",
])

add("Open Redirect Exploitation (12)", [
    "Open redirect via double URL encoding technique",
    "Open redirect via backslash confusion method",
    "Open redirect via protocol-relative URL technique",
    "Open redirect via OAuth callback manipulation",
    "Open redirect via path confusion technique",
    "Open redirect via URL parser differential",
    "Open redirect via fragment manipulation method",
    "Open redirect via login flow exploitation",
    "Open redirect via CRLF injection technique",
    "Open redirect via unicode normalization method",
    "Open redirect via host header manipulation",
    "Open redirect via JavaScript URI exploitation",
])

add("Server Side Template Injection (12)", [
    "SSTI detection via mathematical expression eval",
    "SSTI exploitation via Jinja2 sandbox escape",
    "SSTI exploitation via Twig PHP method call",
    "SSTI exploitation via Freemarker RCE technique",
    "SSTI exploitation via Velocity Java reflection",
    "SSTI exploitation via Smarty PHP code execution",
    "SSTI exploitation via Pebble Java class access",
    "SSTI exploitation via ERB Ruby system command",
    "SSTI exploitation via Mako Python import method",
    "SSTI exploitation via Blade PHP directive abuse",
    "SSTI exploitation via Nunjucks JS code execution",
    "SSTI exploitation via Handlebars lookup helper",
])

add("XXE Advanced Techniques (12)", [
    "XXE via file:// protocol for local file read",
    "XXE via expect:// protocol for command execution",
    "XXE via php://filter for source code read",
    "XXE via SSRF through external DTD loading",
    "XXE via error-based data exfiltration method",
    "XXE via out-of-band HTTP callback technique",
    "XXE via FTP protocol for data exfiltration",
    "XXE via billion laughs DoS exploitation",
    "XXE via document type override technique",
    "XXE via XInclude injection exploitation method",
    "XXE via SVG file upload processing exploitation",
    "XXE via Office document XML processing method",
])

add("Insecure Deserialization Deep (12)", [
    "Deserialization gadget chain discovery technique",
    "Deserialization via ysoserial exploitation method",
    "Deserialization via PHPGGC chain exploitation",
    "Deserialization via .NET gadgets exploitation",
    "Deserialization via Python pickle RCE technique",
    "Deserialization via ViewState tampering method",
    "Deserialization via YAML unsafe load exploitation",
    "Deserialization via XML unmarshalling exploitation",
    "Deserialization via Kryo library exploitation",
    "Deserialization via Jackson polymorphic type abuse",
    "Deserialization via Apache Commons exploitation",
    "Deserialization via Spring framework gadgets",
])

add("Path Traversal Advanced (12)", [
    "Path traversal via dot-dot-slash sequences",
    "Path traversal via URL encoding bypass technique",
    "Path traversal via double encoding exploitation",
    "Path traversal via null byte injection method",
    "Path traversal via Unicode encoding technique",
    "Path traversal via backslash on Windows servers",
    "Path traversal via absolute path exploitation",
    "Path traversal via filename parameter injection",
    "Path traversal via zip file extraction exploit",
    "Path traversal via symlink following technique",
    "Path traversal via file include exploitation",
    "Path traversal via template path manipulation",
])

add("HTTP Header Injection (12)", [
    "HTTP header injection via CRLF in user input",
    "HTTP header injection via newline in parameters",
    "HTTP header injection via host header manipulation",
    "HTTP header injection for cache poisoning attack",
    "HTTP header injection via X-Forwarded headers",
    "HTTP header injection for session fixation",
    "HTTP header injection via referer manipulation",
    "HTTP header injection for XSS via response",
    "HTTP header injection via accept-language field",
    "HTTP header injection for open redirect attack",
    "HTTP header injection via content-type override",
    "HTTP header injection for CORS bypass technique",
])

add("File Inclusion Exploitation (12)", [
    "Local file inclusion via path traversal technique",
    "Remote file inclusion via URL wrapper exploitation",
    "File inclusion via PHP wrapper exploitation method",
    "File inclusion via log poisoning technique",
    "File inclusion via /proc/self/environ exploitation",
    "File inclusion via session file poisoning method",
    "File inclusion via temp file race condition",
    "File inclusion via uploaded file exploitation",
    "File inclusion via zip wrapper exploitation",
    "File inclusion via data wrapper exploitation",
    "File inclusion via expect wrapper for RCE",
    "File inclusion via null byte path truncation",
])

add("SQL Injection Advanced Techniques (12)", [
    "SQL injection via UNION-based data extraction",
    "SQL injection via blind boolean-based technique",
    "SQL injection via blind time-based exploitation",
    "SQL injection via error-based data extraction",
    "SQL injection via stacked queries exploitation",
    "SQL injection via out-of-band DNS exfiltration",
    "SQL injection via second-order exploitation method",
    "SQL injection via JSON parameter manipulation",
    "SQL injection via HTTP header injection technique",
    "SQL injection via ORDER BY clause exploitation",
    "SQL injection via INSERT/UPDATE statement abuse",
    "SQL injection via stored procedure exploitation",
])

add("XSS Advanced Techniques (12)", [
    "XSS via DOM clobbering exploitation technique",
    "XSS via mutation XSS in sanitizer bypass",
    "XSS via SVG animation event handler injection",
    "XSS via JavaScript template literal injection",
    "XSS via Web Component shadow DOM exploitation",
    "XSS via Service Worker registration technique",
    "XSS via PDF.js viewer exploitation method",
    "XSS via PostMessage handler exploitation",
    "XSS via URL fragment exploitation technique",
    "XSS via CSS injection escalation method",
    "XSS via browser extension interaction",
    "XSS via importmap injection exploitation",
])

print(f"Added {len(extra_categories)} categories in batch 2")

add("DOM Based Vulnerability Detection (12)", [
    "DOM XSS via document.location exploitation",
    "DOM XSS via innerHTML assignment technique",
    "DOM XSS via eval() with user input method",
    "DOM XSS via jQuery selector injection technique",
    "DOM XSS via postMessage handler exploitation",
    "DOM clobbering via named access exploitation",
    "DOM-based open redirect via location assignment",
    "DOM-based cookie manipulation exploitation",
    "DOM-based CSRF via XHR manipulation technique",
    "DOM XSS via WebSocket message handling",
    "DOM-based request forgery via AJAX manipulation",
    "DOM XSS via client-side template injection",
])

add("OAuth2 Implementation Flaws (12)", [
    "OAuth2 redirect_uri validation bypass technique",
    "OAuth2 state parameter absence exploitation",
    "OAuth2 scope validation bypass exploitation method",
    "OAuth2 token leakage via referrer header",
    "OAuth2 client credential brute force technique",
    "OAuth2 implicit flow token interception",
    "OAuth2 PKCE downgrade attack exploitation",
    "OAuth2 token exchange confusion exploitation",
    "OAuth2 dynamic registration abuse technique",
    "OAuth2 device flow phishing exploitation",
    "OAuth2 refresh token rotation bypass method",
    "OAuth2 audience restriction bypass technique",
])

add("Two Factor Authentication Bypass (12)", [
    "2FA bypass via response manipulation technique",
    "2FA bypass via brute force with no rate limit",
    "2FA bypass via backup code exploitation method",
    "2FA bypass via session fixation after auth",
    "2FA bypass via direct API endpoint access",
    "2FA bypass via race condition exploitation",
    "2FA bypass via password reset flow skip",
    "2FA bypass via OAuth flow bypass technique",
    "2FA bypass via remember device token forgery",
    "2FA bypass via time-based OTP prediction",
    "2FA bypass via SIM swap exploitation method",
    "2FA bypass via account recovery flow skip",
])

add("Password Reset Vulnerability (12)", [
    "Password reset token prediction exploitation",
    "Password reset via host header injection",
    "Password reset token reuse exploitation method",
    "Password reset via email parameter manipulation",
    "Password reset token expiration bypass technique",
    "Password reset via account enumeration method",
    "Password reset token in referrer leakage",
    "Password reset via IDOR token access technique",
    "Password reset brute force exploitation method",
    "Password reset via race condition exploitation",
    "Password reset flow CSRF exploitation technique",
    "Password reset via response manipulation method",
])

add("Account Takeover Techniques (12)", [
    "Account takeover via credential stuffing detection",
    "Account takeover via session hijacking technique",
    "Account takeover via XSS to session theft",
    "Account takeover via password reset exploitation",
    "Account takeover via OAuth misconfiguration",
    "Account takeover via CSRF in email change",
    "Account takeover via phone number takeover",
    "Account takeover via subdomain takeover chain",
    "Account takeover via IDOR in user settings",
    "Account takeover via JWT manipulation technique",
    "Account takeover via session fixation method",
    "Account takeover via SSO assertion manipulation",
])

add("API Versioning Exploitation (12)", [
    "API version downgrade for auth bypass technique",
    "API deprecated endpoint exploitation method",
    "API version mismatch exploitation technique",
    "API undocumented version discovery method",
    "API beta endpoint security bypass technique",
    "API legacy format acceptance exploitation",
    "API version header manipulation technique",
    "API URL-based version bypass exploitation",
    "API content negotiation version confusion",
    "API backward compatibility exploitation method",
    "API version-specific vulnerability exploitation",
    "API sunset endpoint discovery and exploitation",
])

add("Webhook Security Testing (12)", [
    "Webhook signature validation bypass technique",
    "Webhook replay attack exploitation method",
    "Webhook URL manipulation for SSRF exploitation",
    "Webhook event injection exploitation technique",
    "Webhook race condition exploitation method",
    "Webhook timeout exploitation for DoS attack",
    "Webhook retry logic abuse exploitation method",
    "Webhook payload manipulation exploitation",
    "Webhook endpoint discovery enumeration method",
    "Webhook authentication bypass exploitation",
    "Webhook data exposure via error responses",
    "Webhook configuration injection exploitation",
])

add("Microservice Architecture Exploitation (12)", [
    "Microservice API gateway bypass exploitation",
    "Microservice inter-service auth bypass method",
    "Microservice service discovery exploitation",
    "Microservice circuit breaker manipulation",
    "Microservice sidecar proxy bypass technique",
    "Microservice config service exploitation method",
    "Microservice distributed tracing exploitation",
    "Microservice event bus injection technique",
    "Microservice secret management exploitation",
    "Microservice health endpoint exploitation",
    "Microservice retry storm exploitation method",
    "Microservice API composition exploitation",
])

add("Serverless Function Injection (12)", [
    "Serverless event data injection exploitation",
    "Serverless environment variable manipulation",
    "Serverless layer dependency exploitation method",
    "Serverless VPC resource access exploitation",
    "Serverless IAM role escalation technique",
    "Serverless function alias exploitation method",
    "Serverless provisioned concurrency bypass",
    "Serverless dead letter queue exploitation",
    "Serverless step function manipulation method",
    "Serverless API Gateway integration exploitation",
    "Serverless custom authorizer bypass technique",
    "Serverless event source mapping exploitation",
])

add("Database Security Testing (12)", [
    "Database privilege escalation exploitation method",
    "Database stored procedure exploitation technique",
    "Database trigger manipulation exploitation",
    "Database view security bypass exploitation",
    "Database linked server exploitation technique",
    "Database backup file exposure exploitation",
    "Database replication exploitation technique",
    "Database audit log bypass exploitation method",
    "Database encryption bypass exploitation technique",
    "Database user enumeration exploitation method",
    "Database configuration file exposure detection",
    "Database connection string exposure exploitation",
])

add("Log Injection Exploitation (12)", [
    "Log injection via CRLF for log forging attack",
    "Log injection for SIEM evasion technique",
    "Log injection via HTTP header manipulation",
    "Log injection for false alert generation",
    "Log injection via user agent manipulation",
    "Log injection for audit trail manipulation",
    "Log injection via parameter value poisoning",
    "Log4j JNDI injection exploitation technique",
    "Log injection for compliance violation creation",
    "Log injection via error message manipulation",
    "Log injection for log file XSS exploitation",
    "Log injection via JSON structure manipulation",
])

add("Input Validation Bypass (12)", [
    "Input validation bypass via null byte injection",
    "Input validation bypass via Unicode normalization",
    "Input validation bypass via double encoding method",
    "Input validation bypass via type confusion attack",
    "Input validation bypass via overflow exploitation",
    "Input validation bypass via array manipulation",
    "Input validation bypass via content-type spoofing",
    "Input validation bypass via multipart manipulation",
    "Input validation bypass via charset confusion",
    "Input validation bypass via scientific notation",
    "Input validation bypass via locale exploitation",
    "Input validation bypass via regex backtracking",
])

add("Error Based Information Disclosure (12)", [
    "Error-based SQL injection data extraction method",
    "Error-based path disclosure exploitation technique",
    "Error-based version disclosure detection method",
    "Error-based stack trace information extraction",
    "Error-based database structure disclosure",
    "Error-based configuration exposure technique",
    "Error-based internal IP address disclosure",
    "Error-based library version exposure method",
    "Error-based username enumeration technique",
    "Error-based file system structure disclosure",
    "Error-based API endpoint discovery method",
    "Error-based technology stack fingerprinting",
])

add("Timing Side Channel Attacks (12)", [
    "Timing attack for password comparison bypass",
    "Timing attack for username enumeration method",
    "Timing attack for token validation bypass",
    "Timing attack for HMAC comparison exploitation",
    "Timing attack for database query enumeration",
    "Timing attack for file existence detection",
    "Timing attack for cache hit/miss detection",
    "Timing attack for permission check enumeration",
    "Timing attack for conditional logic detection",
    "Timing attack for encryption oracle exploitation",
    "Timing attack for rate limit detection bypass",
    "Timing attack for geographic location inference",
])

add("Cross Site Scripting Prevention Bypass (12)", [
    "XSS filter bypass via tag attribute injection",
    "XSS filter bypass via event handler variation",
    "XSS filter bypass via encoding exploitation",
    "XSS filter bypass via context breaking technique",
    "XSS filter bypass via template literal injection",
    "XSS filter bypass via SVG/MathML namespace",
    "XSS filter bypass via JavaScript URI protocol",
    "XSS filter bypass via DOM manipulation method",
    "XSS filter bypass via HTML entity exploitation",
    "XSS filter bypass via mutation-based technique",
    "XSS filter bypass via browser quirks exploitation",
    "XSS filter bypass via incomplete sanitization",
])

add("Privilege Escalation via Misconfiguration (12)", [
    "Privilege escalation via default credentials",
    "Privilege escalation via exposed admin interface",
    "Privilege escalation via misconfigured CORS",
    "Privilege escalation via API key scope confusion",
    "Privilege escalation via session cookie manipulation",
    "Privilege escalation via registration flow bypass",
    "Privilege escalation via debug endpoint access",
    "Privilege escalation via backup file access",
    "Privilege escalation via environment variable exposure",
    "Privilege escalation via log file access",
    "Privilege escalation via temp file exploitation",
    "Privilege escalation via configuration endpoint access",
])

add("Denial of Service Patterns (12)", [
    "Application DoS via ReDoS exploitation technique",
    "Application DoS via zip bomb upload method",
    "Application DoS via XML entity expansion attack",
    "Application DoS via large file upload technique",
    "Application DoS via connection exhaustion method",
    "Application DoS via CPU-intensive operation",
    "Application DoS via memory exhaustion technique",
    "Application DoS via recursive query exploitation",
    "Application DoS via rate limit absence exploitation",
    "Application DoS via slowloris attack technique",
    "Application DoS via algorithmic complexity attack",
    "Application DoS via resource lock exploitation",
])

add("Session Management Exploitation (12)", [
    "Session fixation via cookie injection technique",
    "Session prediction via weak random generation",
    "Session hijacking via network sniffing method",
    "Session riding via CSRF exploitation technique",
    "Session timeout absence exploitation method",
    "Session token in URL parameter exposure",
    "Session invalidation failure exploitation",
    "Session token entropy analysis technique",
    "Session concurrent login exploitation method",
    "Session token rotation failure exploitation",
    "Session token scope confusion exploitation",
    "Session binding absence exploitation technique",
])

add("CSRF Advanced Techniques (12)", [
    "CSRF via JSON content type exploitation",
    "CSRF via multipart form data technique",
    "CSRF via subdomain cookie injection method",
    "CSRF via flash-based request exploitation",
    "CSRF via image tag auto-submission technique",
    "CSRF via WebSocket connection exploitation",
    "CSRF via XHR with credentials technique",
    "CSRF via link prefetch exploitation method",
    "CSRF via DNS rebinding combination attack",
    "CSRF token bypass via fixation technique",
    "CSRF via login/logout functionality abuse",
    "CSRF via CORS misconfiguration exploitation",
])

add("Security Header Analysis (12)", [
    "Missing X-Frame-Options header detection",
    "Missing Content-Security-Policy header detection",
    "Missing X-Content-Type-Options header detection",
    "Missing Strict-Transport-Security header detection",
    "Missing Referrer-Policy header detection method",
    "Missing Permissions-Policy header detection",
    "Missing Cross-Origin-Opener-Policy detection",
    "Missing Cross-Origin-Embedder-Policy detection",
    "Missing Cross-Origin-Resource-Policy detection",
    "Misconfigured Access-Control headers detection",
    "Cache-Control sensitive data exposure detection",
    "Set-Cookie security attribute analysis method",
])

add("Secrets Detection in Source (12)", [
    "Hardcoded API key detection in source code",
    "Hardcoded database password detection technique",
    "AWS access key exposure in repository detection",
    "Private SSH key exposure in source detection",
    "JWT signing secret exposure detection method",
    "OAuth client secret exposure in source code",
    "Firebase configuration exposure detection",
    "Stripe secret key exposure detection technique",
    "Twilio auth token exposure detection method",
    "SendGrid API key exposure detection technique",
    "Google Maps API key exposure detection method",
    "Slack webhook URL exposure detection technique",
])

add("Git Repository Security (12)", [
    "Git exposed .git directory exploitation method",
    "Git object file download for source recovery",
    "Git pack file extraction exploitation technique",
    "Git hook script injection exploitation method",
    "Git submodule URL manipulation exploitation",
    "Git LFS endpoint secret exposure detection",
    "Git signed commit bypass exploitation technique",
    "Git branch protection bypass exploitation",
    "Git shallow clone limitation exploitation",
    "Git worktree manipulation exploitation method",
    "Git filter-branch secret exposure detection",
    "Git reflog sensitive data exposure technique",
])

add("CI CD Pipeline Security (12)", [
    "CI pipeline secret injection exploitation",
    "CI pipeline artifact tampering technique",
    "CI pipeline dependency confusion exploitation",
    "CD pipeline deployment credential exposure",
    "CI pipeline build cache poisoning technique",
    "CI pipeline environment variable injection",
    "CD pipeline rollback exploitation technique",
    "CI pipeline parallel execution race condition",
    "CI pipeline matrix strategy exploitation",
    "CD pipeline approval bypass exploitation",
    "CI pipeline custom runner exploitation",
    "CD pipeline canary deployment manipulation",
])

print(f"Total extra categories: {len(extra_categories)}")

add("Infrastructure as Code Security (12)", [
    "Terraform hardcoded secret detection technique",
    "CloudFormation template injection exploitation",
    "Ansible vault password extraction method",
    "Puppet manifest credential exposure detection",
    "Chef cookbook secret exposure technique",
    "Terraform provider misconfiguration exploitation",
    "CloudFormation custom resource exploitation",
    "Ansible playbook privilege escalation method",
    "Terraform remote backend exploitation technique",
    "Pulumi stack secret exposure detection method",
    "CDK construct misconfiguration exploitation",
    "Terraform module supply chain exploitation",
])

add("Container Registry Security (12)", [
    "Container registry unauthorized push exploitation",
    "Container registry image layer secret scanning",
    "Container registry tag mutation exploitation",
    "Container registry manifest list manipulation",
    "Container registry garbage collection bypass",
    "Container registry webhook manipulation method",
    "Container registry quota bypass exploitation",
    "Container registry scope elevation technique",
    "Container registry cross-repository mounting",
    "Container registry content trust bypass method",
    "Container registry catalog enumeration technique",
    "Container registry token scope exploitation",
])

add("Kubernetes Network Policy (12)", [
    "Kubernetes network policy bypass via DNS",
    "Kubernetes network policy egress bypass technique",
    "Kubernetes network policy label manipulation",
    "Kubernetes network policy namespace bypass",
    "Kubernetes network policy pod selector confusion",
    "Kubernetes network policy port range exploitation",
    "Kubernetes network policy CIDR manipulation",
    "Kubernetes network policy ingress bypass method",
    "Kubernetes network policy default deny bypass",
    "Kubernetes network policy precedence exploitation",
    "Kubernetes network policy service mesh bypass",
    "Kubernetes network policy exception exploitation",
])

add("Secrets Management Exploitation (12)", [
    "HashiCorp Vault authentication bypass technique",
    "HashiCorp Vault token escalation exploitation",
    "AWS Secrets Manager unauthorized access method",
    "Azure Key Vault access policy exploitation",
    "GCP Secret Manager IAM bypass technique",
    "HashiCorp Vault lease manipulation exploitation",
    "AWS Parameter Store unauthorized access method",
    "CyberArk vault credential extraction technique",
    "Kubernetes external secrets exploitation method",
    "SOPS encrypted file key extraction technique",
    "Sealed secrets controller exploitation method",
    "Doppler secrets platform exploitation technique",
])

add("Monitoring Observability Exploitation (12)", [
    "Prometheus metrics endpoint data exposure",
    "Grafana dashboard unauthorized access method",
    "Jaeger tracing data exposure exploitation",
    "ELK stack Kibana unauthorized access technique",
    "Datadog API key exposure exploitation method",
    "New Relic agent configuration exploitation",
    "PagerDuty webhook manipulation technique",
    "Sentry error tracking data exposure method",
    "CloudWatch log group unauthorized access",
    "OpenTelemetry collector manipulation technique",
    "StatsD metric injection exploitation method",
    "Zipkin trace data exposure exploitation",
])

add("Backup Recovery Exploitation (12)", [
    "Database backup file exposure exploitation",
    "Application backup archive exploitation method",
    "Cloud snapshot unauthorized access technique",
    "Configuration backup exposure exploitation",
    "Source code backup file discovery method",
    "Virtual machine snapshot exploitation technique",
    "Backup credential rotation absence detection",
    "Disaster recovery testing exploitation method",
    "Backup encryption absence detection technique",
    "Incremental backup chain exploitation method",
    "Backup retention policy exploitation technique",
    "Cross-region backup access exploitation method",
])

add("API Documentation Exploitation (12)", [
    "Swagger UI unauthorized access exploitation",
    "OpenAPI specification exposure exploitation",
    "GraphQL introspection data exploitation method",
    "API documentation hidden endpoint discovery",
    "Postman collection exposure exploitation",
    "API blueprint file exposure exploitation method",
    "WADL file exposure exploitation technique",
    "WSDL file exposure exploitation method",
    "API changelog exposure for version targeting",
    "API mock server exploitation technique",
    "API sandbox environment exploitation method",
    "API rate limit documentation exploitation",
])

add("Single Sign On Exploitation (12)", [
    "SSO redirect URI manipulation exploitation",
    "SSO token exchange confusion exploitation",
    "SSO IdP metadata manipulation technique",
    "SSO assertion consumer service exploitation",
    "SSO relay state manipulation exploitation",
    "SSO attribute mapping exploitation technique",
    "SSO session synchronization exploitation",
    "SSO federated logout exploitation method",
    "SSO cross-IdP confusion exploitation technique",
    "SSO provisioning flow exploitation method",
    "SSO certificate rollover exploitation technique",
    "SSO multi-factor step-up bypass exploitation",
])

add("GraphQL Subscription Security (12)", [
    "GraphQL subscription authorization bypass method",
    "GraphQL subscription data leakage exploitation",
    "GraphQL subscription injection exploitation",
    "GraphQL subscription DoS via excessive subscriptions",
    "GraphQL subscription filter bypass technique",
    "GraphQL subscription reconnection exploitation",
    "GraphQL subscription event injection method",
    "GraphQL subscription memory exhaustion attack",
    "GraphQL subscription schema discovery method",
    "GraphQL subscription transport manipulation",
    "GraphQL subscription rate limit bypass technique",
    "GraphQL subscription authentication bypass method",
])

add("Headless Browser Exploitation (12)", [
    "Headless browser SSRF via navigation exploitation",
    "Headless browser file read via file protocol",
    "Headless browser XSS in screenshot rendering",
    "Headless browser network access exploitation",
    "Headless browser credential extraction method",
    "Headless browser JavaScript execution exploitation",
    "Headless browser DevTools protocol exploitation",
    "Headless browser PDF generation exploitation",
    "Headless browser cookie jar manipulation",
    "Headless browser extension exploitation method",
    "Headless browser resource timing exploitation",
    "Headless browser WebGL fingerprinting abuse",
])

add("Data Exfiltration Techniques (12)", [
    "Data exfiltration via DNS query encoding method",
    "Data exfiltration via HTTP header manipulation",
    "Data exfiltration via timing side channel",
    "Data exfiltration via error message manipulation",
    "Data exfiltration via browser history detection",
    "Data exfiltration via CSS-based technique",
    "Data exfiltration via WebRTC ICE candidates",
    "Data exfiltration via service worker manipulation",
    "Data exfiltration via battery API exploitation",
    "Data exfiltration via performance API technique",
    "Data exfiltration via ambient light sensor abuse",
    "Data exfiltration via accelerometer data technique",
])

add("Third Party Integration Security (12)", [
    "Third-party OAuth integration exploitation",
    "Third-party webhook endpoint exploitation method",
    "Third-party API key exposure detection technique",
    "Third-party SDK vulnerability exploitation",
    "Third-party payment integration bypass method",
    "Third-party SSO integration exploitation technique",
    "Third-party storage integration exploitation",
    "Third-party email service exploitation method",
    "Third-party CDN integration exploitation technique",
    "Third-party analytics integration exploitation",
    "Third-party authentication integration bypass",
    "Third-party notification service exploitation",
])

# Write additional categories to the roadmap file
check_num = last_num + 1
with open(OUTPUT, 'a') as f:
    for cat_name, checks in extra_categories:
        f.write(f"## {cat_name}\n")
        for check in checks:
            f.write(f"{check_num}. {check}\n")
            check_num += 1
        f.write("\n")

print(f"Appended {check_num - last_num - 1} more checks ({len(extra_categories)} categories)")
print(f"Total checks now: {check_num - 1}")
