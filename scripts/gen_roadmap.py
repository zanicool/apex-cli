#!/usr/bin/env python3
"""Generate roadmap-500.md with 315+ categories and 3500+ checks."""

import os
import sys

OUTPUT = "/home/zani/git/apex-cli/docs/roadmap-500.md"

categories = []

def add(name, checks):
    categories.append((name, checks))

def gen_checks(prefix, items):
    """Generate check descriptions from a list of short names."""
    return [f"{prefix} {item}" for item in items]

# ============ WEB APPLICATION (50 modules) ============

add("HTTP Response Splitting (12)", [
    "HTTP response splitting via CRLF in header value",
    "HTTP response splitting via encoded CRLF sequences",
    "Header injection via newline in cookie value",
    "HTTP response splitting in redirect Location header",
    "CRLF injection in custom response headers",
    "Response splitting via URL parameter reflection in headers",
    "HTTP header injection via user-agent reflection",
    "Response splitting in Set-Cookie header value",
    "CRLF injection in Content-Disposition filename",
    "HTTP response splitting via multiline header folding",
    "Header injection via null byte truncation",
    "Response splitting in X-Forwarded-For reflection",
])

add("Content Sniffing Attacks (12)", [
    "MIME sniffing via missing X-Content-Type-Options",
    "Content type confusion with polyglot HTML/JS",
    "SVG content sniffing to XSS escalation",
    "PDF content sniffing for phishing delivery",
    "XML content type confusion attack vector",
    "Image file content sniffing to script execution",
    "CSV injection via content type mismatch",
    "HTA content sniffing in legacy browser mode",
    "Content sniffing bypass via partial content response",
    "MIME confusion in file download endpoints",
    "Content type mismatch in API responses",
    "Polyglot JPEG/JavaScript content sniffing attack",
])

add("MIME Confusion Exploitation (12)", [
    "MIME type mismatch in file upload validation",
    "Double extension MIME confusion bypass",
    "MIME type override via content-type header manipulation",
    "MIME confusion in email attachment handling",
    "SVG MIME confusion for stored XSS delivery",
    "MIME sniffing in cached HTTP responses",
    "Content negotiation MIME confusion vector",
    "MIME type confusion in WebSocket upgrade request",
    "Multipart MIME boundary confusion attack",
    "MIME confusion via charset parameter injection",
    "MIME type confusion in service worker scope",
    "Application octet-stream MIME confusion attack",
])

add("Cookie Manipulation Advanced (12)", [
    "Cookie injection via HTTP response splitting",
    "Cookie value overflow truncation attack",
    "Cookie jar overflow forcing session logout",
    "Cookie fixation via subdomain injection",
    "Cookie manipulation via meta tag injection",
    "Double-submit cookie bypass techniques",
    "Cookie value deserialization exploitation",
    "Cookie prefix bypass for Host and Secure cookies",
    "Cookie scope manipulation via path confusion",
    "Same-site cookie bypass via top-level navigation",
    "Cookie manipulation via JavaScript prototype pollution",
    "Cookie replay attack in session management",
])

add("Cookie Tossing Attacks (12)", [
    "Cookie tossing from sibling subdomain override",
    "Cookie tossing to override session token value",
    "Cookie tossing via wildcard domain cookie injection",
    "Cookie tossing CSRF bypass technique",
    "Cookie tossing to poison CDN cache keys",
    "Cookie tossing via public suffix confusion",
    "Subdomain cookie tossing for account takeover",
    "Cookie tossing to bypass same-site restrictions",
    "Cookie tossing via DNS rebinding combination attack",
    "Cookie tossing to manipulate load balancer affinity",
    "Cookie tossing for JWT token confusion attack",
    "Cookie tossing via CDN origin confusion vector",
])

add("Cookie Scope Exploitation (12)", [
    "Overly broad cookie domain scope detection",
    "Cookie path traversal scope expansion attack",
    "Secure flag missing on authentication cookies",
    "HttpOnly flag missing allowing JavaScript access",
    "SameSite attribute missing or misconfigured detection",
    "Cookie scope leak via subdomain enumeration",
    "Persistent cookie with excessive lifetime detection",
    "Cookie scope confusion in multi-tenant applications",
    "Third-party cookie scope information leakage",
    "Cookie scope manipulation via port number confusion",
    "Cookie scope bypass via URL encoding tricks",
    "Cookie domain scope inheritance exploitation vector",
])

add("IDOR Advanced Techniques (12)", [
    "IDOR via UUID prediction using timestamp correlation",
    "IDOR via GraphQL node ID enumeration technique",
    "IDOR in file download with sequential naming pattern",
    "IDOR via API version downgrade removing auth checks",
    "IDOR in webhook delivery endpoint manipulation",
    "IDOR via batch bulk operation endpoints",
    "IDOR in export report generation with user ID leak",
    "IDOR via email change confirmation link prediction",
    "IDOR in notification preference endpoint access",
    "IDOR via cursor-based pagination manipulation",
    "IDOR in multi-step workflow state manipulation",
    "IDOR via object relationship traversal technique",
])

add("XML Injection Deep (12)", [
    "XML injection in SOAP request body manipulation",
    "XML entity expansion denial of service billion laughs",
    "XML injection in RSS Atom feed generation endpoint",
    "XML injection via SVG file upload processing",
    "XML injection in SAML assertion manipulation attack",
    "XXE via DOCTYPE in XML file upload endpoint",
    "XML injection in Office document processing pipeline",
    "Blind XXE via out-of-band data exfiltration channel",
    "XML injection in sitemap.xml generation endpoint",
    "XML injection via Content-Type switching to XML",
    "XML injection in configuration file parsing logic",
    "XXE via parameter entities for file read access",
])

add("XPath Injection Advanced (12)", [
    "XPath injection in authentication bypass attack",
    "Blind XPath injection via boolean-based extraction",
    "XPath injection in search functionality exploitation",
    "XPath 2.0 function injection for data extraction",
    "XPath injection via XML attribute manipulation",
    "XPath injection in XACML policy evaluation bypass",
    "XPath injection with namespace prefix abuse technique",
    "Out-of-band XPath injection via doc function call",
    "XPath injection in REST API XML parameter handling",
    "XPath injection via error-based data extraction",
    "XPath injection in SOAP message routing logic",
    "XPath injection combined with XXE chaining attack",
])

add("XSLT Injection Exploitation (12)", [
    "XSLT injection for server-side code execution",
    "XSLT injection via stylesheet parameter manipulation",
    "XSLT injection for local file read via document func",
    "XSLT injection in PDF generation pipeline exploitation",
    "XSLT injection for SSRF via xsl include directive",
    "XSLT injection in XML transformation API endpoint",
    "XSLT injection for information disclosure attack",
    "XSLT 2.0 injection with system-property abuse",
    "XSLT injection via malicious stylesheet file upload",
    "XSLT injection in report generation engine logic",
    "XSLT injection combined with XXE amplification",
    "XSLT injection for remote code execution via extensions",
])

add("LDAP Injection Advanced (12)", [
    "LDAP injection in user search functionality bypass",
    "Blind LDAP injection via response timing analysis",
    "LDAP injection to bypass authentication mechanism",
    "LDAP injection in group membership query manipulation",
    "LDAP injection via Distinguished Name manipulation",
    "LDAP injection in Active Directory query exploitation",
    "LDAP injection for privilege escalation attack",
    "LDAP injection in password reset flow exploitation",
    "LDAP injection via filter concatenation technique",
    "LDAP injection in LDAP-based authorization bypass",
    "LDAP injection to enumerate directory structure",
    "LDAP injection combined with Kerberos exploitation",
])

add("NoSQL Injection Advanced (12)", [
    "MongoDB operator injection via gt ne regex operators",
    "NoSQL injection in aggregation pipeline manipulation",
    "NoSQL injection via JSON body parameter manipulation",
    "CouchDB view injection via map function code",
    "NoSQL injection in GraphQL resolver query execution",
    "Redis command injection via protocol abuse technique",
    "Cassandra CQL injection in batch statement execution",
    "DynamoDB condition expression injection attack",
    "NoSQL injection via prototype pollution to query object",
    "Elasticsearch query DSL injection exploitation",
    "NoSQL injection in real-time database rules bypass",
    "Firebase security rules bypass via crafted query params",
])

add("SSRF Advanced Techniques (12)", [
    "SSRF via DNS rebinding to bypass IP allowlist",
    "SSRF through URL parser differential exploitation",
    "SSRF via redirect chain to internal service access",
    "SSRF in PDF generation via HTML injection technique",
    "SSRF via IPv6 address confusion and mapping",
    "SSRF through cloud metadata endpoint access attempt",
    "SSRF via URL shortener redirect exploitation chain",
    "SSRF in webhook URL validation bypass technique",
    "SSRF via protocol smuggling with gopher and dict",
    "SSRF through SVG image processing xlink href abuse",
    "SSRF via SSRF-to-RCE chain through internal API calls",
    "Blind SSRF detection via response timing differences",
])

add("DNS Rebinding Advanced (12)", [
    "DNS rebinding to access internal network services",
    "DNS rebinding via short TTL record manipulation",
    "DNS rebinding to bypass same-origin policy check",
    "DNS rebinding against IoT device web interfaces",
    "DNS rebinding for cloud metadata service access",
    "DNS rebinding via multiple A record rotation trick",
    "DNS rebinding combined with service worker attack",
    "DNS rebinding to exploit internal REST API endpoints",
    "DNS rebinding via CNAME chain manipulation technique",
    "DNS rebinding for router admin panel unauthorized access",
    "DNS rebinding against Docker daemon API endpoint",
    "DNS rebinding via browser DNS cache pollution attack",
])

add("HTTP Desync Attacks (12)", [
    "HTTP request smuggling via CL.TE desync technique",
    "HTTP request smuggling via TE.CL desync attack",
    "HTTP/2 to HTTP/1.1 downgrade desync exploitation",
    "HTTP desync via ambiguous Content-Length headers",
    "Request smuggling via Transfer-Encoding obfuscation",
    "HTTP desync for web cache poisoning exploitation",
    "Request smuggling to bypass WAF security rules",
    "HTTP desync via chunked encoding manipulation attack",
    "Request smuggling for credential theft attack vector",
    "HTTP desync in reverse proxy misconfiguration",
    "Request smuggling via HTTP/2 CONTINUATION frames abuse",
    "HTTP desync for request routing manipulation attack",
])

add("Request Tunneling Attacks (12)", [
    "Request tunnel via HTTP/2 stream multiplexing abuse",
    "Request tunnel through WebSocket upgrade exploitation",
    "Request tunnel via CONNECT method proxy abuse",
    "Request tunnel in proxy chain exploitation technique",
    "Request tunnel via chunked transfer encoding abuse",
    "Request tunnel for internal port scanning discovery",
    "Request tunnel through load balancer bypass technique",
    "Request tunnel via HTTP upgrade mechanism exploitation",
    "Request tunnel in CDN origin exposure attack",
    "Request tunnel via HEAD method response confusion",
    "Request tunnel through OPTIONS pre-flight abuse",
    "Request tunnel for firewall bypass technique vector",
])

add("Response Queue Poisoning (12)", [
    "Response queue poisoning via HTTP desync attack",
    "Response queue poisoning for session hijacking attack",
    "Response queue desynchronization exploitation technique",
    "Poisoned response delivery to other connected users",
    "Response queue manipulation via keep-alive connection abuse",
    "Response queue poisoning in shared hosting environment",
    "Response queue confusion via HTTP pipelining abuse",
    "Response queue poisoning for reflected XSS delivery",
    "Response queue manipulation via HEAD GET method confusion",
    "Response queue poisoning in CDN infrastructure attack",
    "Response queue timing attack for sensitive data theft",
    "Response queue poisoning via HTTP trailer headers abuse",
])

add("WebSocket Injection Attacks (12)", [
    "WebSocket message injection via cross-site hijacking",
    "WebSocket origin validation bypass exploitation",
    "WebSocket message tampering in transit manipulation",
    "WebSocket injection for stored XSS delivery attack",
    "WebSocket protocol confusion exploitation vector",
    "WebSocket injection in chat application exploitation",
    "WebSocket injection via binary frame manipulation",
    "Cross-site WebSocket hijacking for data theft",
    "WebSocket injection for server command execution",
    "WebSocket injection in real-time trading manipulation",
    "WebSocket authentication bypass via upgrade request",
    "WebSocket injection for privilege escalation attack",
])

add("Socket IO Abuse Techniques (12)", [
    "Socket.IO event injection via crafted emit payload",
    "Socket.IO namespace authorization bypass technique",
    "Socket.IO room joining without proper permission",
    "Socket.IO broadcast message interception attack",
    "Socket.IO acknowledgment callback exploitation vector",
    "Socket.IO transport upgrade manipulation attack",
    "Socket.IO session fixation via handshake manipulation",
    "Socket.IO denial of service via event flooding attack",
    "Socket.IO volatile event race condition exploitation",
    "Socket.IO binary data injection in event payload",
    "Socket.IO middleware bypass via transport switching",
    "Socket.IO reconnection token theft exploitation",
])

add("gRPC Exploitation Techniques (12)", [
    "gRPC reflection service information disclosure attack",
    "gRPC authentication bypass via metadata manipulation",
    "gRPC message size limit denial of service attack",
    "gRPC stream exhaustion resource consumption attack",
    "gRPC deadline propagation abuse for timeout attack",
    "gRPC interceptor bypass via direct service call",
    "gRPC protobuf deserialization exploitation vector",
    "gRPC server-side streaming resource exhaustion",
    "gRPC bidirectional stream hijacking technique",
    "gRPC channel credential theft exploitation attack",
    "gRPC health check endpoint information leakage",
    "gRPC error message sensitive information disclosure",
])

print(f"Web app part 1: {len(categories)} categories so far")

add("File Upload Advanced Exploitation (12)", [
    "File upload bypass via null byte in filename",
    "File upload bypass via double extension technique",
    "File upload bypass via Content-Type header manipulation",
    "File upload bypass via magic bytes prepending",
    "File upload race condition exploitation technique",
    "File upload via chunked multipart boundary confusion",
    "File upload path traversal via filename manipulation",
    "File upload to webroot via symlink following",
    "File upload bypass via case sensitivity exploitation",
    "File upload bypass via Unicode normalization tricks",
    "File upload bypass via alternate data stream abuse",
    "File upload size limit bypass via chunked upload",
])

add("Polyglot File Attacks (12)", [
    "JPEG polyglot with embedded JavaScript payload",
    "PNG polyglot with HTML content for XSS delivery",
    "PDF polyglot with JavaScript auto-execution code",
    "GIF polyglot file for cross-origin data theft",
    "SVG polyglot with embedded script execution",
    "ZIP polyglot with dual-format interpretation",
    "TIFF polyglot with embedded executable content",
    "BMP polyglot for browser content sniffing abuse",
    "WebP polyglot with script injection payload",
    "ICO polyglot file for favicon-based attacks",
    "DICOM polyglot for medical system exploitation",
    "WAV polyglot with embedded script content",
])

add("Archive Extraction Attacks (12)", [
    "ZIP slip path traversal in archive extraction",
    "Tar symlink exploitation in extraction process",
    "ZIP bomb denial of service via compression ratio",
    "Archive extraction race condition exploitation",
    "Nested archive expansion denial of service",
    "Archive extraction with absolute path override",
    "Zip file name encoding confusion exploitation",
    "Archive extraction permission preservation attack",
    "Self-extracting archive code execution vector",
    "Archive extraction via crafted CPIO format abuse",
    "7z archive extraction path traversal technique",
    "RAR archive extraction symbolic link following",
])

add("Prototype Pollution Advanced (12)", [
    "Prototype pollution via deep merge operations",
    "Prototype pollution via JSON.parse with reviver",
    "Prototype pollution to RCE via child_process",
    "Prototype pollution in template engine exploitation",
    "Prototype pollution via query string parser abuse",
    "Prototype pollution for authentication bypass",
    "Prototype pollution via lodash merge vulnerability",
    "Prototype pollution in Express.js middleware",
    "Prototype pollution to XSS via innerHTML gadget",
    "Prototype pollution via Object.assign exploitation",
    "Prototype pollution in webpack configuration",
    "Prototype pollution chain to privilege escalation",
])

add("Class Pollution Attacks (12)", [
    "Python class pollution via __class__ attribute",
    "Python class pollution in Pydantic models",
    "Python class pollution via merge operations",
    "Ruby class pollution via method_missing abuse",
    "Java class pollution via deserialization gadgets",
    "PHP class pollution via property overwrite",
    "Class pollution in ORM model manipulation",
    "Class pollution via dynamic attribute assignment",
    "Class pollution for sandbox escape technique",
    "Class pollution in dependency injection container",
    "Class pollution via metaclass manipulation abuse",
    "Class pollution for access control bypass attack",
])

add("CSS Injection Attacks (12)", [
    "CSS injection for data exfiltration via selectors",
    "CSS injection via attribute selector timing attack",
    "CSS injection for CSRF token extraction technique",
    "CSS injection via @import for external data leak",
    "CSS injection in email HTML for tracking pixel",
    "CSS injection for keylogging via font-face unicode",
    "CSS injection via style attribute in sanitized HTML",
    "CSS injection for sensitive data screenshot capture",
    "CSS injection via calc() and var() exploitation",
    "CSS injection in SVG style element for XSS chain",
    "CSS injection via @font-face src URL data exfil",
    "CSS injection for form auto-fill data extraction",
])

add("Dangling Markup Injection (12)", [
    "Dangling markup via unclosed img tag for data capture",
    "Dangling markup via base tag injection for URL theft",
    "Dangling markup via unclosed textarea for page capture",
    "Dangling markup via form action override technique",
    "Dangling markup via meta refresh for redirect injection",
    "Dangling markup via unclosed attribute for DOM capture",
    "Dangling markup via button formaction override attack",
    "Dangling markup via object data attribute hijacking",
    "Dangling markup via iframe src attribute injection",
    "Dangling markup via link href stylesheet injection",
    "Dangling markup via input formaction override technique",
    "Dangling markup for CSP bypass via base-uri exploitation",
])

add("Relative Path Override (12)", [
    "Relative path override for stylesheet injection attack",
    "RPO via path confusion in URL routing mechanism",
    "RPO for JavaScript file inclusion manipulation",
    "RPO via encoded slash in path segment exploitation",
    "RPO in framework routing path normalization bypass",
    "RPO for CSS-based data exfiltration technique",
    "RPO via double-encoded path traversal confusion",
    "RPO in single-page application routing exploitation",
    "RPO via dot segment path manipulation technique",
    "RPO for service worker scope expansion attack",
    "RPO via backslash path confusion in Windows servers",
    "RPO for import map manipulation in ES modules",
])

add("Email Injection Advanced (12)", [
    "Email header injection via CC/BCC field manipulation",
    "Email injection for spam relay exploitation technique",
    "Email injection via newline in subject field",
    "Email injection for phishing delivery mechanism",
    "Email injection via MIME boundary manipulation",
    "Email injection in contact form to arbitrary recipient",
    "Email injection via encoded header value exploitation",
    "Email injection for email spoofing delivery attack",
    "Email injection via attachment manipulation technique",
    "Email injection in password reset flow exploitation",
    "Email injection for email bombing attack technique",
    "Email injection via Return-Path header manipulation",
])

add("SMTP Smuggling Attacks (12)", [
    "SMTP smuggling via dot-stuffing confusion technique",
    "SMTP smuggling between different MTA implementations",
    "SMTP smuggling for SPF bypass exploitation attack",
    "SMTP smuggling via CRLF sequence manipulation",
    "SMTP smuggling for DKIM signature confusion",
    "SMTP smuggling via pipelining abuse technique",
    "SMTP smuggling to bypass email authentication",
    "SMTP smuggling via DATA command manipulation",
    "SMTP smuggling for DMARC bypass exploitation",
    "SMTP smuggling in multi-hop mail relay chain",
    "SMTP smuggling via BDAT command confusion attack",
    "SMTP smuggling for internal email injection delivery",
])

add("PDF Generation SSRF (12)", [
    "PDF generation SSRF via img src URL injection",
    "PDF generation SSRF via CSS background-url directive",
    "PDF generation SSRF via link href stylesheet injection",
    "PDF generation SSRF via iframe src attribute",
    "PDF generation SSRF via SVG xlink:href attribute",
    "PDF generation SSRF via script src remote inclusion",
    "PDF generation SSRF via HTML embed tag exploitation",
    "PDF generation SSRF via font-face src URL injection",
    "PDF generation SSRF via video/audio source tags",
    "PDF generation SSRF via object data URL injection",
    "PDF generation local file read via file protocol",
    "PDF generation SSRF via XML external entity in XHTML",
])

add("HTML to PDF Injection (12)", [
    "HTML-to-PDF XSS via JavaScript execution in renderer",
    "HTML-to-PDF local file read via anchor tag navigation",
    "HTML-to-PDF SSRF via external resource loading",
    "HTML-to-PDF header footer injection exploitation",
    "HTML-to-PDF page break injection for content theft",
    "HTML-to-PDF CSS media print exploitation technique",
    "HTML-to-PDF annotation injection for phishing",
    "HTML-to-PDF form field injection exploitation",
    "HTML-to-PDF metadata injection for tracking",
    "HTML-to-PDF JavaScript-based port scanning",
    "HTML-to-PDF via wkhtmltopdf specific exploitation",
    "HTML-to-PDF via Puppeteer/Chrome specific attacks",
])

add("Image Processing SSRF (12)", [
    "ImageMagick SSRF via MVG delegate processing",
    "ImageMagick SSRF via SVG xlink:href exploitation",
    "ImageMagick RCE via MSL file processing attack",
    "Ghostscript SSRF via PostScript output device",
    "Ghostscript RCE via pipe output exploitation",
    "LibreOffice SSRF via embedded macro execution",
    "PIL/Pillow SSRF via image URL processing",
    "GraphicsMagick SSRF via delegate command injection",
    "Sharp/libvips SSRF via SVG processing pipeline",
    "FFmpeg SSRF via HLS playlist processing attack",
    "ExifTool command injection via crafted metadata",
    "Image processing SSRF via ICC profile URL fetch",
])

add("Regex Injection ReDoS (12)", [
    "ReDoS via catastrophic backtracking in user regex",
    "Regex injection to bypass validation patterns",
    "ReDoS in email validation regular expression",
    "Regex injection for path traversal bypass technique",
    "ReDoS via nested quantifier exploitation attack",
    "Regex injection in search query pattern matching",
    "ReDoS via overlapping alternation in regex pattern",
    "Regex injection for WAF rule bypass technique",
    "ReDoS in URL validation regular expression pattern",
    "Regex injection via flag manipulation exploitation",
    "ReDoS via polynomial time complexity exploitation",
    "Regex injection combined with prototype pollution",
])

add("Mass Assignment Advanced (12)", [
    "Mass assignment to elevate user role privilege",
    "Mass assignment to modify account balance value",
    "Mass assignment via hidden form field injection",
    "Mass assignment in GraphQL mutation input types",
    "Mass assignment via JSON merge patch exploitation",
    "Mass assignment to set admin flag on user object",
    "Mass assignment via XML parameter binding abuse",
    "Mass assignment in REST API PUT/PATCH operations",
    "Mass assignment to modify ownership of resources",
    "Mass assignment via array parameter index abuse",
    "Mass assignment in ORM model attribute injection",
    "Mass assignment to bypass read-only field protection",
])

add("Property Injection Attacks (12)", [
    "Property injection via JSON body additional fields",
    "Property injection in MongoDB update operations",
    "Property injection via query parameter binding",
    "Property injection in ActiveRecord model creation",
    "Property injection via form multipart field addition",
    "Property injection in Sequelize model creation",
    "Property injection via PATCH request body fields",
    "Property injection in Mongoose document creation",
    "Property injection via GraphQL input object extension",
    "Property injection in Hibernate entity binding",
    "Property injection via XML element addition attack",
    "Property injection in TypeORM entity operations",
])

add("Second Order SQL Injection (12)", [
    "Second-order SQLi via stored username in query",
    "Second-order SQLi via profile field in admin report",
    "Second-order SQLi via filename stored in database",
    "Second-order SQLi via address field in shipping query",
    "Second-order SQLi via comment field in moderation",
    "Second-order SQLi via registration data in export",
    "Second-order SQLi via tag/label in search index",
    "Second-order SQLi via webhook URL in notification",
    "Second-order SQLi via display name in audit log",
    "Second-order SQLi via custom field in aggregation",
    "Second-order SQLi via imported CSV data in query",
    "Second-order SQLi via cached search result rendering",
])

add("Second Order XSS Attacks (12)", [
    "Second-order XSS via stored username in admin panel",
    "Second-order XSS via profile bio in search results",
    "Second-order XSS via filename in file listing page",
    "Second-order XSS via error message in log viewer",
    "Second-order XSS via email subject in inbox display",
    "Second-order XSS via API key name in dashboard",
    "Second-order XSS via webhook name in configuration",
    "Second-order XSS via team name in organization page",
    "Second-order XSS via custom header value in response",
    "Second-order XSS via referrer URL in analytics",
    "Second-order XSS via user-agent in admin logs view",
    "Second-order XSS via imported data in report output",
])

add("Second Order SSRF Attacks (12)", [
    "Second-order SSRF via stored webhook URL callback",
    "Second-order SSRF via avatar URL in image proxy",
    "Second-order SSRF via RSS feed URL in aggregator",
    "Second-order SSRF via import URL in batch processor",
    "Second-order SSRF via callback URL in payment flow",
    "Second-order SSRF via logo URL in email template",
    "Second-order SSRF via sitemap URL in SEO crawler",
    "Second-order SSRF via redirect URL in link shortener",
    "Second-order SSRF via schema URL in validator",
    "Second-order SSRF via font URL in document renderer",
    "Second-order SSRF via manifest URL in PWA builder",
    "Second-order SSRF via preview URL in link unfurler",
])

add("HTTP Parameter Fragmentation (12)", [
    "HTTP parameter pollution via duplicate params",
    "Parameter fragmentation across query and body",
    "Parameter priority confusion in framework routing",
    "HTTP parameter array injection exploitation",
    "Parameter fragmentation via encoding differences",
    "HTTP parameter truncation exploitation technique",
    "Parameter fragmentation in multipart vs urlencoded",
    "HTTP parameter override via header injection",
    "Parameter fragmentation across proxies in chain",
    "HTTP parameter type confusion array vs string",
    "Parameter fragmentation via middleware ordering",
    "HTTP parameter collision in load balanced setup",
])

add("Verb Tunneling Method Override (12)", [
    "HTTP method override via X-HTTP-Method-Override header",
    "Verb tunneling via _method parameter in form body",
    "Method override via X-Method-Override header injection",
    "HTTP TRACE method enabled for XST exploitation",
    "Verb tunneling to bypass method-based access control",
    "Method override via custom header in REST framework",
    "HTTP method confusion in CORS preflight bypass",
    "Verb tunneling via POST body to simulate DELETE",
    "Method override to bypass WAF HTTP method rules",
    "HTTP PATCH method injection for partial update abuse",
    "Verb tunneling via URL suffix override technique",
    "Method override in GraphQL endpoint method restriction",
])

add("Error Handling Information Leak (12)", [
    "Stack trace disclosure via unhandled exception",
    "Database error message with query structure leak",
    "Debug mode enabled in production environment",
    "Verbose error revealing file system paths",
    "Error message disclosing internal IP addresses",
    "Exception handling revealing framework version",
    "Error response with database connection strings",
    "Debug endpoint accessible in production deployment",
    "Error message revealing API key or token values",
    "Verbose error with source code snippet exposure",
    "Error handling revealing backend service topology",
    "Debug information in HTTP response headers leak",
])

add("Debug Endpoint Exposure (12)", [
    "Spring Boot Actuator endpoints publicly accessible",
    "Django debug toolbar exposed in production",
    "PHP phpinfo() page accessible publicly",
    "ASP.NET Elmah error log endpoint exposure",
    "Express.js debug middleware in production mode",
    "Ruby on Rails web console endpoint exposed",
    "Laravel Telescope debug dashboard accessible",
    "Symfony profiler bar accessible in production",
    "Flask debugger PIN bypass exploitation technique",
    "Next.js _next/data debug information exposure",
    "GraphQL introspection enabled in production API",
    "Kubernetes dashboard exposed without authentication",
])

add("Session Puzzling Attacks (12)", [
    "Session variable overwrite via registration flow",
    "Session puzzling via password reset token reuse",
    "Session variable confusion in multi-step workflow",
    "Session puzzling for authentication bypass technique",
    "Session variable overwrite via profile update flow",
    "Session puzzling via OAuth callback state confusion",
    "Session variable conflict in concurrent requests",
    "Session puzzling for privilege escalation attack",
    "Session variable reuse across different features",
    "Session puzzling via cart checkout flow confusion",
    "Session variable pollution in shared session store",
    "Session puzzling for CSRF protection bypass",
])

add("Session Donation Attacks (12)", [
    "Session donation via pre-authenticated session token",
    "Session donation for login CSRF exploitation",
    "Session donation via cookie injection technique",
    "Session donation to capture victim credentials",
    "Session donation via subdomain cookie injection",
    "Session donation for payment method theft attack",
    "Session donation via QR code login exploitation",
    "Session donation in SSO flow manipulation",
    "Session donation for address book pollution",
    "Session donation via persistent session token",
    "Session donation for credit card harvesting",
    "Session donation via WebSocket session sharing",
])

add("Cross Origin Attacks Advanced (12)", [
    "CORS misconfiguration with wildcard origin reflection",
    "CORS null origin bypass for local file exploitation",
    "Cross-origin resource timing side channel attack",
    "CORS preflight cache poisoning exploitation",
    "Cross-origin information leak via error events",
    "CORS credential theft via subdomain takeover",
    "Cross-origin pixel perfect timing attack",
    "CORS bypass via DNS rebinding technique combination",
    "Cross-origin frame counting information disclosure",
    "CORS misconfiguration in internal API endpoints",
    "Cross-origin WebSocket connection hijacking attack",
    "CORS bypass via browser extension exploitation",
])

add("JWT Advanced kid Injection (12)", [
    "JWT kid parameter SQL injection exploitation",
    "JWT kid parameter path traversal to known file",
    "JWT kid parameter pointing to empty signing key",
    "JWT kid parameter SSRF via remote key fetch",
    "JWT kid parameter directory traversal attack",
    "JWT kid parameter null byte injection technique",
    "JWT kid parameter pointing to /dev/null for bypass",
    "JWT kid parameter command injection exploitation",
    "JWT kid parameter LDAP injection for key lookup",
    "JWT kid parameter Redis key injection technique",
    "JWT kid parameter pointing to symmetric key file",
    "JWT kid parameter injection for algorithm confusion",
])

add("JWT JWK Header Injection (12)", [
    "JWT jwk header self-signed key injection attack",
    "JWT jwk embedded public key bypass technique",
    "JWT jku URL injection for remote key retrieval",
    "JWT x5u URL injection for certificate chain bypass",
    "JWT x5c embedded certificate chain manipulation",
    "JWT algorithm confusion RS256 to HS256 attack",
    "JWT none algorithm bypass exploitation technique",
    "JWT header injection via typ parameter abuse",
    "JWT claim injection via nested JWT in header",
    "JWT signature stripping attack technique",
    "JWT key ID confusion in multi-tenant environment",
    "JWT audience claim bypass in federated system",
])

add("OAuth Advanced Token Theft (12)", [
    "OAuth authorization code interception via redirect",
    "OAuth implicit flow token theft via open redirect",
    "OAuth token theft via referrer header leakage",
    "OAuth PKCE downgrade attack for code interception",
    "OAuth device flow polling exploitation technique",
    "OAuth token exchange confusion attack vector",
    "OAuth dynamic client registration exploitation",
    "OAuth pushed authorization request bypass",
    "OAuth token binding bypass technique exploitation",
    "OAuth scope upgrade via consent screen manipulation",
    "OAuth state parameter fixation for CSRF attack",
    "OAuth authorization server mix-up attack vector",
])

add("SAML Advanced Exploitation (12)", [
    "SAML signature exclusion attack for assertion forge",
    "SAML assertion injection via XML comment trick",
    "SAML response wrapping attack technique",
    "SAML signature value manipulation exploitation",
    "SAML recipient validation bypass attack vector",
    "SAML assertion replay with timestamp manipulation",
    "SAML NameID injection for impersonation attack",
    "SAML condition bypass via NotBefore NotOnOrAfter",
    "SAML issuer spoofing in multi-IdP environment",
    "SAML encrypted assertion key confusion attack",
    "SAML assertion cloning via reference manipulation",
    "SAML XSLT transformation injection in assertion",
])

add("OpenID Connect Advanced (12)", [
    "OIDC ID token injection via response manipulation",
    "OIDC hybrid flow code/token confusion attack",
    "OIDC userinfo endpoint data leakage exploitation",
    "OIDC dynamic registration for redirect hijacking",
    "OIDC front-channel logout CSRF exploitation",
    "OIDC back-channel logout token forging attempt",
    "OIDC acr claim bypass for step-up auth skip",
    "OIDC nonce reuse exploitation for replay attack",
    "OIDC request object injection via request_uri",
    "OIDC token endpoint authentication bypass",
    "OIDC sector identifier validation bypass",
    "OIDC aggregated claims injection exploitation",
])

add("Privilege Escalation via API (12)", [
    "API privilege escalation via role parameter injection",
    "API privilege escalation via admin endpoint discovery",
    "API privilege escalation via GraphQL mutation abuse",
    "API privilege escalation via version downgrade",
    "API privilege escalation via batch request bypass",
    "API privilege escalation via header injection technique",
    "API privilege escalation via rate limit bypass",
    "API privilege escalation via API key scope confusion",
    "API privilege escalation via CORS exploitation chain",
    "API privilege escalation via webhook callback abuse",
    "API privilege escalation via token scope manipulation",
    "API privilege escalation via metadata endpoint access",
])

add("Horizontal Privilege Escalation (12)", [
    "Horizontal privesc via predictable resource IDs",
    "Horizontal privesc via API parameter manipulation",
    "Horizontal privesc via shared resource access",
    "Horizontal privesc via session token prediction",
    "Horizontal privesc via email enumeration technique",
    "Horizontal privesc via account linking confusion",
    "Horizontal privesc via search result data exposure",
    "Horizontal privesc via notification routing error",
    "Horizontal privesc via export functionality abuse",
    "Horizontal privesc via invitation link prediction",
    "Horizontal privesc via shared cache exploitation",
    "Horizontal privesc via debug endpoint data access",
])

add("Vertical Privilege Escalation (12)", [
    "Vertical privesc via forced browsing to admin panel",
    "Vertical privesc via JWT role claim manipulation",
    "Vertical privesc via cookie value role injection",
    "Vertical privesc via parameter tampering in request",
    "Vertical privesc via insecure direct function call",
    "Vertical privesc via race condition in role check",
    "Vertical privesc via API gateway routing bypass",
    "Vertical privesc via default admin credentials",
    "Vertical privesc via registration flow role override",
    "Vertical privesc via OAuth scope escalation attack",
    "Vertical privesc via path traversal to admin routes",
    "Vertical privesc via deserialization gadget chain",
])

add("Multi Tenant Isolation Bypass (12)", [
    "Tenant isolation bypass via shared database query",
    "Tenant isolation bypass via subdomain enumeration",
    "Tenant isolation bypass via API key confusion",
    "Tenant isolation bypass via shared cache poisoning",
    "Tenant isolation bypass via background job leakage",
    "Tenant isolation bypass via file storage path traversal",
    "Tenant isolation bypass via webhook endpoint confusion",
    "Tenant isolation bypass via shared message queue",
    "Tenant isolation bypass via search index cross-read",
    "Tenant isolation bypass via DNS misconfiguration",
    "Tenant isolation bypass via shared session store",
    "Tenant isolation bypass via log aggregation exposure",
])

print(f"After web app: {len(categories)} categories")

# ============ INFRASTRUCTURE (40 modules) ============

add("Kubernetes RBAC Exploitation (12)", [
    "Kubernetes RBAC privilege escalation via role binding",
    "Kubernetes RBAC wildcard permission exploitation",
    "Kubernetes service account token theft technique",
    "Kubernetes RBAC escalation via impersonation API",
    "Kubernetes namespace escape via RBAC misconfiguration",
    "Kubernetes RBAC audit log bypass technique",
    "Kubernetes cluster-admin binding discovery",
    "Kubernetes RBAC escalation via CSR approval permission",
    "Kubernetes pod security policy bypass via RBAC",
    "Kubernetes RBAC lateral movement via service accounts",
    "Kubernetes admission controller bypass via RBAC",
    "Kubernetes RBAC escalation via node proxy access",
])

add("Kubernetes Secrets Exploitation (12)", [
    "Kubernetes secret extraction from etcd datastore",
    "Kubernetes secret exposure in environment variables",
    "Kubernetes secret access via service account mount",
    "Kubernetes secret theft via pod exec privilege",
    "Kubernetes secret exposure in container filesystem",
    "Kubernetes secret access via API server request",
    "Kubernetes secret extraction from pod spec labels",
    "Kubernetes secret exposure in helm release history",
    "Kubernetes secret access via backup exfiltration",
    "Kubernetes secret rotation detection absence",
    "Kubernetes secret encryption at rest verification",
    "Kubernetes secret exposure via debug endpoints",
])

add("Kubernetes Service Mesh (12)", [
    "Kubernetes service mesh mTLS bypass technique",
    "Kubernetes service mesh sidecar injection abuse",
    "Kubernetes service mesh traffic interception attack",
    "Kubernetes service mesh authorization policy bypass",
    "Kubernetes service mesh egress policy circumvention",
    "Kubernetes service mesh control plane compromise",
    "Kubernetes service mesh certificate manipulation",
    "Kubernetes service mesh retry policy abuse for DoS",
    "Kubernetes service mesh header injection via envoy",
    "Kubernetes service mesh traffic mirroring exploitation",
    "Kubernetes service mesh fault injection abuse",
    "Kubernetes service mesh observability data theft",
])

add("Docker Container Escape (12)", [
    "Docker container escape via privileged mode exploitation",
    "Docker container escape via mounted Docker socket",
    "Docker container escape via kernel exploit technique",
    "Docker container escape via cgroup release_agent",
    "Docker container escape via procfs mount abuse",
    "Docker container escape via cap_sys_admin exploitation",
    "Docker container escape via runC vulnerability",
    "Docker container escape via device mount abuse",
    "Docker container escape via user namespace misconfiguration",
    "Docker container escape via AppArmor profile bypass",
    "Docker container escape via seccomp profile disable",
    "Docker container escape via shared namespace exploitation",
])

add("Docker Socket Registry (12)", [
    "Docker socket exposure via API endpoint access",
    "Docker socket exploitation for host access technique",
    "Docker registry unauthorized image push exploitation",
    "Docker registry image layer inspection for secrets",
    "Docker socket abuse for container creation attack",
    "Docker registry tag manipulation exploitation",
    "Docker socket privilege escalation via volume mount",
    "Docker registry manifest manipulation attack",
    "Docker socket API version downgrade exploitation",
    "Docker registry cross-repository blob mounting",
    "Docker socket network namespace manipulation",
    "Docker registry content trust bypass technique",
])

add("AWS IAM Exploitation (12)", [
    "AWS IAM privilege escalation via policy attachment",
    "AWS IAM role chaining for cross-account access",
    "AWS IAM access key exposure in source code",
    "AWS IAM assume role with permissive trust policy",
    "AWS IAM policy wildcard resource exploitation",
    "AWS IAM escalation via lambda execution role",
    "AWS IAM boundary policy bypass technique",
    "AWS IAM temporary credentials extraction method",
    "AWS IAM cross-service confused deputy attack",
    "AWS IAM escalation via EC2 instance profile",
    "AWS IAM OIDC provider misconfiguration abuse",
    "AWS IAM policy condition bypass exploitation",
])

add("AWS Lambda Exploitation (12)", [
    "AWS Lambda function URL authentication bypass",
    "AWS Lambda layer secret extraction technique",
    "AWS Lambda environment variable exposure method",
    "AWS Lambda execution role privilege escalation",
    "AWS Lambda event injection via trigger manipulation",
    "AWS Lambda cold start timing side channel",
    "AWS Lambda function policy overly permissive",
    "AWS Lambda resource policy misconfiguration",
    "AWS Lambda VPC configuration for internal access",
    "AWS Lambda runtime API abuse for data theft",
    "AWS Lambda extension for persistent backdoor",
    "AWS Lambda concurrency exhaustion DoS attack",
])

add("AWS S3 Advanced (12)", [
    "AWS S3 bucket policy misconfiguration detection",
    "AWS S3 ACL permission escalation exploitation",
    "AWS S3 presigned URL manipulation attack technique",
    "AWS S3 bucket enumeration via DNS and HTTP",
    "AWS S3 object versioning for deleted data access",
    "AWS S3 event notification hijacking technique",
    "AWS S3 replication configuration exploitation",
    "AWS S3 access point policy bypass technique",
    "AWS S3 batch operation privilege escalation",
    "AWS S3 inventory report information disclosure",
    "AWS S3 lifecycle policy abuse for data manipulation",
    "AWS S3 object Lambda exploitation technique",
])

add("AWS EC2 SSRF Metadata (12)", [
    "AWS EC2 metadata service v1 token theft via SSRF",
    "AWS EC2 IMDSv2 bypass via proxy chain technique",
    "AWS EC2 metadata role credential extraction",
    "AWS EC2 userdata secrets exposure via metadata",
    "AWS EC2 metadata service hop limit bypass",
    "AWS EC2 SSRF via application proxy to metadata",
    "AWS EC2 metadata identity document exfiltration",
    "AWS EC2 metadata network interface information leak",
    "AWS EC2 instance connect SSH key injection via SSRF",
    "AWS EC2 metadata security credential rotation detection",
    "AWS EC2 SSRF via container metadata endpoint",
    "AWS EC2 metadata service IPv6 endpoint access",
])

add("GCP IAM Metadata (12)", [
    "GCP IAM service account key exposure detection",
    "GCP IAM privilege escalation via setIamPolicy",
    "GCP metadata server token theft via SSRF",
    "GCP IAM impersonation via token creator role",
    "GCP metadata project-level SSH key injection",
    "GCP IAM organization policy bypass technique",
    "GCP metadata custom attribute information leak",
    "GCP IAM conditional binding bypass exploitation",
    "GCP metadata startup-script secret extraction",
    "GCP IAM domain-wide delegation abuse technique",
    "GCP metadata service account scope enumeration",
    "GCP IAM workload identity federation bypass",
])

add("GCP Storage Functions (12)", [
    "GCP Cloud Storage bucket enumeration technique",
    "GCP Cloud Storage ACL misconfiguration detection",
    "GCP Cloud Storage signed URL manipulation",
    "GCP Cloud Functions authentication bypass",
    "GCP Cloud Functions environment variable exposure",
    "GCP Cloud Storage uniform bucket-level access bypass",
    "GCP Cloud Functions event injection exploitation",
    "GCP Cloud Storage retention policy manipulation",
    "GCP Cloud Functions VPC connector exploitation",
    "GCP Cloud Storage object versioning data access",
    "GCP Cloud Functions invoker permission escalation",
    "GCP Cloud Storage lifecycle rule abuse technique",
])

add("Azure AD Advanced Exploitation (12)", [
    "Azure AD token manipulation via FOCI exploitation",
    "Azure AD consent grant attack for permission theft",
    "Azure AD application proxy SSRF exploitation",
    "Azure AD PRT theft via device registration abuse",
    "Azure AD conditional access bypass techniques",
    "Azure AD B2C custom policy manipulation attack",
    "Azure AD device code phishing exploitation method",
    "Azure AD managed identity token extraction",
    "Azure AD directory role escalation technique",
    "Azure AD application credential rotation detection",
    "Azure AD cross-tenant access abuse method",
    "Azure AD service principal privilege escalation",
])

add("Azure Storage Functions (12)", [
    "Azure Blob Storage SAS token misconfiguration",
    "Azure Blob Storage container enumeration technique",
    "Azure Functions authentication level bypass",
    "Azure Functions managed identity token theft",
    "Azure Storage account key exposure detection",
    "Azure Functions binding injection exploitation",
    "Azure Blob Storage snapshot data access technique",
    "Azure Functions durable orchestration manipulation",
    "Azure Storage shared access policy exploitation",
    "Azure Functions proxy configuration abuse",
    "Azure Blob Storage soft-delete data recovery",
    "Azure Functions extension bundle exploitation",
])

add("Terraform CloudFormation Secrets (12)", [
    "Terraform state file secret exposure detection",
    "Terraform remote state unauthorized access",
    "CloudFormation stack output secret exposure",
    "Terraform provider credential in state file",
    "CloudFormation custom resource credential leak",
    "Terraform plan file sensitive data exposure",
    "CloudFormation drift detection for secret changes",
    "Terraform workspace isolation bypass technique",
    "CloudFormation nested stack secret propagation",
    "Terraform module registry supply chain attack",
    "CloudFormation macro for code injection technique",
    "Terraform backend configuration credential theft",
])

add("CI CD GitHub Actions (12)", [
    "GitHub Actions secret exfiltration via workflow",
    "GitHub Actions pull_request_target exploitation",
    "GitHub Actions artifact poisoning technique",
    "GitHub Actions OIDC token theft exploitation",
    "GitHub Actions workflow_dispatch injection attack",
    "GitHub Actions self-hosted runner escape technique",
    "GitHub Actions environment protection bypass",
    "GitHub Actions cache poisoning exploitation method",
    "GitHub Actions composite action supply chain",
    "GitHub Actions permissions escalation technique",
    "GitHub Actions reusable workflow exploitation",
    "GitHub Actions GITHUB_TOKEN privilege abuse",
])

add("CI CD GitLab Jenkins (12)", [
    "GitLab CI pipeline secret variable exposure",
    "GitLab CI runner escape via Docker executor",
    "Jenkins credential theft via build step injection",
    "GitLab CI dependency proxy cache poisoning",
    "Jenkins remote code execution via Groovy console",
    "GitLab CI artifact secret extraction technique",
    "Jenkins pipeline shared library exploitation",
    "GitLab CI protected branch bypass technique",
    "Jenkins build parameter injection attack",
    "GitLab CI multi-project pipeline manipulation",
    "Jenkins API token exposure and abuse technique",
    "GitLab CI environment variable injection attack",
])

add("Network Segmentation Bypass (12)", [
    "Network segmentation bypass via VLAN hopping",
    "Network segmentation bypass via ARP spoofing",
    "Network segmentation bypass via DNS tunneling",
    "Network segmentation bypass via ICMP tunneling",
    "Network segmentation bypass via HTTP tunnel proxy",
    "Network segmentation bypass via IPv6 transition",
    "Network segmentation bypass via cloud VPC peering",
    "Network segmentation bypass via shared services",
    "Network segmentation bypass via VPN split tunnel",
    "Network segmentation bypass via container networking",
    "Network segmentation bypass via wireless bridging",
    "Network segmentation bypass via MAC spoofing",
])

add("IPv6 Exploitation Techniques (12)", [
    "IPv6 neighbor discovery spoofing attack vector",
    "IPv6 router advertisement injection exploitation",
    "IPv6 extension header exploitation technique",
    "IPv6 fragmentation overlap exploitation attack",
    "IPv6 dual-stack bypass for security control evasion",
    "IPv6 address space scanning methodology",
    "IPv6 DHCPv6 spoofing for MITM positioning",
    "IPv6 flow label covert channel exploitation",
    "IPv6 tunneling for network segmentation bypass",
    "IPv6 multicast abuse for reconnaissance",
    "IPv6 privacy extension tracking technique",
    "IPv6 DNS64/NAT64 bypass exploitation method",
])

add("DNS Exfiltration Tunneling (12)", [
    "DNS exfiltration via TXT record query encoding",
    "DNS tunneling via CNAME record data transfer",
    "DNS exfiltration via subdomain label encoding",
    "DNS tunneling for C2 communication channel",
    "DNS exfiltration via MX record abuse technique",
    "DNS tunneling via NULL record type usage",
    "DNS exfiltration via EDNS0 OPT record abuse",
    "DNS tunneling detection evasion techniques",
    "DNS exfiltration via DNS-over-HTTPS encapsulation",
    "DNS tunneling via fragmented response assembly",
    "DNS exfiltration via SRV record data encoding",
    "DNS tunneling for firewall bypass technique",
])

add("Firewall Bypass Techniques (12)", [
    "Firewall bypass via HTTP protocol encapsulation",
    "Firewall bypass via DNS rebinding technique",
    "Firewall bypass via IPv6 transition mechanisms",
    "Firewall bypass via fragmentation exploitation",
    "Firewall bypass via application layer tunneling",
    "Firewall bypass via cloud metadata proxy access",
    "Firewall bypass via WebSocket protocol upgrade",
    "Firewall bypass via alternate port discovery",
    "Firewall bypass via ICMP tunneling technique",
    "Firewall bypass via connection state manipulation",
    "Firewall bypass via time-based rule exploitation",
    "Firewall bypass via source IP spoofing method",
])

add("Load Balancer Exploitation (12)", [
    "Load balancer session affinity manipulation",
    "Load balancer health check endpoint abuse",
    "Load balancer direct backend access technique",
    "Load balancer HTTP/2 downgrade exploitation",
    "Load balancer connection pooling confusion",
    "Load balancer cache poisoning via headers",
    "Load balancer SSL termination exploitation",
    "Load balancer sticky session token manipulation",
    "Load balancer virtual host routing confusion",
    "Load balancer algorithm bias exploitation",
    "Load balancer failover trigger manipulation",
    "Load balancer WAF bypass via backend direct access",
])

add("Reverse Proxy Misconfiguration (12)", [
    "Reverse proxy path normalization bypass technique",
    "Reverse proxy hop-by-hop header exploitation",
    "Reverse proxy internal routing information leak",
    "Reverse proxy cache key manipulation attack",
    "Reverse proxy backend connection reuse abuse",
    "Reverse proxy header injection via underscore",
    "Reverse proxy X-Forwarded-For trust exploitation",
    "Reverse proxy absolute URL routing confusion",
    "Reverse proxy chunk extension manipulation",
    "Reverse proxy timeout-based request smuggling",
    "Reverse proxy ACL bypass via path manipulation",
    "Reverse proxy WebSocket upgrade exploitation",
])

add("Service Mesh Exploitation (12)", [
    "Istio authorization policy bypass technique",
    "Istio sidecar injection manipulation attack",
    "Linkerd identity spoofing via mTLS bypass",
    "Istio egress gateway circumvention method",
    "Linkerd service profile rate limit bypass",
    "Istio VirtualService routing manipulation",
    "Service mesh control plane credential theft",
    "Istio telemetry data exfiltration technique",
    "Linkerd tap functionality abuse for data theft",
    "Istio EnvoyFilter injection exploitation method",
    "Service mesh canary deployment manipulation",
    "Istio multi-cluster trust domain exploitation",
])

add("Message Queue Exploitation (12)", [
    "RabbitMQ management interface unauthorized access",
    "RabbitMQ queue injection via exchange binding",
    "Kafka consumer group manipulation technique",
    "Kafka topic ACL bypass exploitation method",
    "Redis Pub/Sub message interception technique",
    "Redis command injection via protocol exploitation",
    "RabbitMQ shovel plugin credential extraction",
    "Kafka Connect task configuration injection",
    "Redis Sentinel authentication bypass technique",
    "RabbitMQ federation link manipulation attack",
    "Kafka Schema Registry unauthorized modification",
    "Redis Cluster slot manipulation exploitation",
])

add("Database Service Exploitation (12)", [
    "Redis unauthorized command execution exposure",
    "Memcached amplification via stats command",
    "Elasticsearch cluster unauthorized API access",
    "Redis Lua script injection exploitation method",
    "Memcached binary protocol exploitation technique",
    "Elasticsearch snapshot repository data theft",
    "Redis module loading for code execution attack",
    "Memcached SASL authentication bypass technique",
    "Elasticsearch field-level security bypass method",
    "Redis ACL configuration bypass exploitation",
    "Memcached UDP reflection amplification attack",
    "Elasticsearch cross-cluster search exploitation",
])

add("LDAP Server Exploitation (12)", [
    "LDAP server anonymous bind information disclosure",
    "LDAP server unencrypted bind credential theft",
    "LDAP server referral following exploitation",
    "LDAP server search filter injection attack",
    "LDAP server password policy enumeration",
    "LDAP server modify operation for privilege escalation",
    "LDAP server extended operation abuse technique",
    "LDAP server StartTLS downgrade exploitation",
    "LDAP server paged result manipulation attack",
    "LDAP server schema discovery for exploitation",
    "LDAP server replication credential extraction",
    "LDAP server control extension exploitation method",
])

add("FTP SFTP Misconfiguration (12)", [
    "FTP anonymous login sensitive data access",
    "FTP bounce attack for port scanning technique",
    "SFTP chroot jail escape via symlink technique",
    "FTP PASV mode for internal network mapping",
    "SFTP authorized key injection exploitation",
    "FTP clear-text credential interception attack",
    "SFTP subsystem configuration manipulation",
    "FTP directory traversal via path manipulation",
    "SFTP file permission escalation technique",
    "FTP SITE command injection exploitation method",
    "SFTP forwarding agent exploitation technique",
    "FTP active mode for firewall bypass technique",
])

add("SNMP Community String (12)", [
    "SNMP community string brute force discovery",
    "SNMP v1/v2c community string information disclosure",
    "SNMP write community string exploitation",
    "SNMP MIB walking for infrastructure reconnaissance",
    "SNMP trap community string interception",
    "SNMP bulk get operations for data exfiltration",
    "SNMP set operations for configuration manipulation",
    "SNMP v3 authentication bypass technique",
    "SNMP agent misconfiguration exploitation",
    "SNMP reflection amplification attack vector",
    "SNMP extended information disclosure technique",
    "SNMP device credential extraction via MIB",
])

add("SMTP Relay Advanced (12)", [
    "SMTP open relay detection for spam abuse",
    "SMTP relay via NTLM authentication bypass",
    "SMTP relay via VRFY command user enumeration",
    "SMTP relay via EXPN command for list discovery",
    "SMTP relay authentication bypass technique",
    "SMTP relay via backup MX exploitation method",
    "SMTP relay for phishing campaign delivery",
    "SMTP relay via STARTTLS downgrade attack",
    "SMTP relay header injection exploitation",
    "SMTP relay via null sender address abuse",
    "SMTP relay for SPF bypass exploitation technique",
    "SMTP relay via AUTH PLAIN credential theft",
])

print(f"After infrastructure: {len(categories)} categories")

# ============ MODERN STACK (40 modules) ============

add("Next.js Middleware Exploitation (12)", [
    "Next.js middleware bypass via direct page access",
    "Next.js middleware authentication bypass technique",
    "Next.js middleware SSRF via rewrite rules",
    "Next.js middleware header injection exploitation",
    "Next.js middleware regex path bypass method",
    "Next.js middleware rate limit bypass technique",
    "Next.js middleware geolocation spoofing attack",
    "Next.js middleware response manipulation vector",
    "Next.js middleware cookie manipulation technique",
    "Next.js middleware edge function timeout abuse",
    "Next.js middleware locale routing bypass method",
    "Next.js middleware request body access limitation bypass",
])

add("Next.js RSC Server Actions (12)", [
    "Next.js server action parameter injection attack",
    "Next.js RSC payload manipulation exploitation",
    "Next.js server action CSRF bypass technique",
    "Next.js RSC streaming data interception method",
    "Next.js server action file upload exploitation",
    "Next.js RSC cache poisoning via flight data",
    "Next.js server action race condition exploitation",
    "Next.js RSC error boundary information disclosure",
    "Next.js server action validation bypass technique",
    "Next.js RSC client reference manipulation attack",
    "Next.js server action redirect manipulation",
    "Next.js RSC server component injection vector",
])

add("Nuxt.js Vulnerabilities (12)", [
    "Nuxt.js server route authentication bypass",
    "Nuxt.js nitro handler injection exploitation",
    "Nuxt.js middleware order of execution bypass",
    "Nuxt.js asyncData SSRF via external fetch",
    "Nuxt.js plugin injection exploitation technique",
    "Nuxt.js module configuration exposure method",
    "Nuxt.js static generation data leakage attack",
    "Nuxt.js runtime config secret exposure vector",
    "Nuxt.js auto-import manipulation exploitation",
    "Nuxt.js payload extraction via __NUXT__ variable",
    "Nuxt.js dev tools endpoint exposure technique",
    "Nuxt.js composable state pollution attack",
])

add("Remix Framework Security (12)", [
    "Remix loader function SSRF exploitation method",
    "Remix action function CSRF bypass technique",
    "Remix resource route authentication bypass",
    "Remix session cookie manipulation exploitation",
    "Remix splat route path traversal attack vector",
    "Remix defer streaming data interception method",
    "Remix meta function injection exploitation",
    "Remix error boundary information disclosure",
    "Remix form validation bypass via direct fetch",
    "Remix nested route data leakage technique",
    "Remix redirect manipulation exploitation method",
    "Remix file upload route exploitation technique",
])

add("SvelteKit Security Issues (12)", [
    "SvelteKit server route authentication bypass",
    "SvelteKit hooks handle function exploitation",
    "SvelteKit form action CSRF bypass technique",
    "SvelteKit load function SSRF exploitation method",
    "SvelteKit endpoint parameter injection attack",
    "SvelteKit cookies API manipulation technique",
    "SvelteKit page data serialization exploitation",
    "SvelteKit error page information disclosure",
    "SvelteKit prerender data leakage vulnerability",
    "SvelteKit adapter-node configuration exposure",
    "SvelteKit handle fetch manipulation technique",
    "SvelteKit snapshot data injection exploitation",
])

add("Astro SSR Vulnerabilities (12)", [
    "Astro SSR endpoint authentication bypass method",
    "Astro middleware chain bypass exploitation",
    "Astro API route parameter injection attack",
    "Astro content collection data leakage vector",
    "Astro SSR redirect manipulation exploitation",
    "Astro island hydration data injection technique",
    "Astro image optimization SSRF exploitation",
    "Astro dev toolbar endpoint exposure method",
    "Astro server-side rendering XSS technique",
    "Astro adapter configuration exposure vector",
    "Astro edge function timeout exploitation",
    "Astro environment variable exposure method",
])

add("Deno Deploy Security (12)", [
    "Deno Deploy permission model bypass technique",
    "Deno Deploy KV store unauthorized access method",
    "Deno Deploy edge function SSRF exploitation",
    "Deno Deploy environment variable exposure",
    "Deno Deploy cron job manipulation exploitation",
    "Deno Deploy queue message injection technique",
    "Deno Deploy BroadcastChannel abuse method",
    "Deno Deploy WebSocket hijacking exploitation",
    "Deno Deploy fetch API SSRF technique",
    "Deno Deploy module import manipulation attack",
    "Deno Deploy Worker permission escalation",
    "Deno Deploy Subprocess spawn exploitation",
])

add("Bun Runtime Security (12)", [
    "Bun runtime FFI exploitation technique",
    "Bun shell command injection via shell API",
    "Bun file system API path traversal attack",
    "Bun HTTP server request smuggling technique",
    "Bun SQLite binding injection exploitation",
    "Bun WebSocket server hijacking method",
    "Bun native module loading exploitation",
    "Bun password hashing timing attack vector",
    "Bun TCP socket manipulation technique",
    "Bun glob pattern injection exploitation",
    "Bun semver parsing confusion attack",
    "Bun test runner code injection technique",
])

add("Edge Computing Attacks (12)", [
    "Edge function cold start race condition abuse",
    "Edge worker secret exposure via timing attack",
    "Edge function CPU limit bypass for crypto mining",
    "Edge computing data residency violation method",
    "Edge function cache poisoning exploitation",
    "Edge worker memory isolation bypass technique",
    "Edge function geolocation bypass exploitation",
    "Edge computing tenant isolation bypass method",
    "Edge function environment variable enumeration",
    "Edge worker WebCrypto API abuse technique",
    "Edge function request coalescing exploitation",
    "Edge computing deployment rollback manipulation",
])

add("Serverless Advanced Exploitation (12)", [
    "Serverless cold start timing side channel attack",
    "Serverless layer secret extraction technique",
    "Serverless function event injection exploitation",
    "Serverless execution environment persistence",
    "Serverless function chaining privilege escalation",
    "Serverless resource policy misconfiguration abuse",
    "Serverless function timeout exploitation for DoS",
    "Serverless concurrency exhaustion attack technique",
    "Serverless function memory dump exploitation",
    "Serverless trigger permission escalation method",
    "Serverless function version alias manipulation",
    "Serverless dead letter queue data theft method",
])

add("WebAssembly Security (12)", [
    "WebAssembly linear memory overflow exploitation",
    "WebAssembly table function type confusion attack",
    "WebAssembly import function hijacking technique",
    "WebAssembly stack overflow exploitation method",
    "WebAssembly global variable manipulation attack",
    "WebAssembly WASI filesystem escape technique",
    "WebAssembly shared memory race condition abuse",
    "WebAssembly module instantiation exploitation",
    "WebAssembly exception handling manipulation",
    "WebAssembly reference type confusion attack",
    "WebAssembly SIMD side channel exploitation",
    "WebAssembly component model capability bypass",
])

add("Service Worker Attacks (12)", [
    "Service worker cache poisoning exploitation method",
    "Service worker scope expansion via path confusion",
    "Service worker fetch event manipulation attack",
    "Service worker persistence for XSS amplification",
    "Service worker navigation interception technique",
    "Service worker background sync abuse method",
    "Service worker push subscription hijacking",
    "Service worker importScripts injection attack",
    "Service worker clients.claim exploitation method",
    "Service worker update mechanism manipulation",
    "Service worker foreign fetch abuse technique",
    "Service worker registration scope bypass attack",
])

add("Web Push Notification Abuse (12)", [
    "Web push subscription endpoint enumeration",
    "Web push notification phishing delivery method",
    "Web push key pair manipulation exploitation",
    "Web push notification spamming technique",
    "Web push subscription transfer theft method",
    "Web push payload encryption bypass technique",
    "Web push VAPID key spoofing exploitation",
    "Web push TTL manipulation for message delay",
    "Web push topic manipulation for message override",
    "Web push urgency manipulation exploitation",
    "Web push notification click hijacking technique",
    "Web push service worker registration abuse",
])

add("Payment API Advanced (12)", [
    "Stripe webhook signature bypass exploitation",
    "PayPal IPN manipulation for payment bypass",
    "Payment amount manipulation via race condition",
    "Stripe customer portal session hijacking",
    "PayPal order approval flow manipulation",
    "Adyen shopper reference enumeration technique",
    "Payment currency confusion exploitation method",
    "Stripe Connect account manipulation attack",
    "PayPal subscription modification exploitation",
    "Payment gateway callback URL manipulation",
    "Stripe payment intent state confusion attack",
    "Payment processor response tampering technique",
])

add("Cryptocurrency Wallet Security (12)", [
    "Crypto wallet seed phrase exposure detection",
    "Crypto wallet private key extraction technique",
    "Web3 wallet connection hijacking method",
    "Crypto wallet transaction signing manipulation",
    "MetaMask RPC endpoint hijacking attack",
    "Crypto wallet address spoofing via clipboard",
    "Web3 wallet phishing via permit signature",
    "Crypto wallet key derivation weakness detection",
    "Crypto wallet backup exposure via cloud sync",
    "Web3 wallet arbitrary message signing exploitation",
    "Crypto wallet session token manipulation attack",
    "Web3 wallet dApp connection persistence abuse",
])

add("NFT Smart Contract Interaction (12)", [
    "NFT contract reentrancy exploitation technique",
    "NFT metadata manipulation for phishing attack",
    "NFT approval front-running exploitation method",
    "NFT royalty bypass via direct transfer technique",
    "NFT marketplace signature replay exploitation",
    "NFT contract access control bypass method",
    "NFT flash loan manipulation exploitation",
    "NFT collection enumeration for whale targeting",
    "NFT contract upgrade proxy manipulation attack",
    "NFT merkle proof forgery exploitation technique",
    "NFT marketplace order cancellation race condition",
    "NFT contract view function data extraction",
])

add("AI ML Pipeline Security (12)", [
    "ML model file deserialization RCE exploitation",
    "AI pipeline training data poisoning detection",
    "ML model API unauthorized inference access",
    "AI pipeline feature store data leakage method",
    "ML model version rollback manipulation attack",
    "AI pipeline GPU resource theft exploitation",
    "ML model endpoint authentication bypass method",
    "AI pipeline experiment tracking data exposure",
    "ML model adversarial input evasion technique",
    "AI pipeline artifact storage unauthorized access",
    "ML model hyperparameter injection exploitation",
    "AI pipeline notebook server code execution",
])

add("Vector Database Exploitation (12)", [
    "Vector DB unauthorized collection access method",
    "Vector DB embedding extraction for model theft",
    "Vector DB similarity search bypass technique",
    "Vector DB metadata filter injection exploitation",
    "Vector DB payload injection via embedding",
    "Vector DB access control bypass for data theft",
    "Vector DB backup exfiltration exploitation method",
    "Vector DB schema discovery for reconnaissance",
    "Vector DB distance threshold manipulation attack",
    "Vector DB batch operation privilege escalation",
    "Vector DB tenant isolation bypass technique",
    "Vector DB API key exposure and abuse method",
])

add("LLM Advanced Exploitation (12)", [
    "LLM system prompt extraction via indirect injection",
    "LLM tool use manipulation for unauthorized actions",
    "LLM data exfiltration via output manipulation",
    "LLM jailbreak via multi-turn context confusion",
    "LLM function calling parameter injection attack",
    "LLM training data extraction via memorization",
    "LLM safety filter bypass via encoding techniques",
    "LLM plugin exploitation for privilege escalation",
    "LLM context window overflow for instruction override",
    "LLM multi-modal injection via image embedding",
    "LLM agent loop exploitation for resource exhaustion",
    "LLM chain-of-thought manipulation exploitation",
])

add("RAG Poisoning Advanced (12)", [
    "RAG document injection for answer manipulation",
    "RAG embedding space poisoning technique",
    "RAG retrieval bypass via adversarial document",
    "RAG context injection for prompt manipulation",
    "RAG knowledge base unauthorized modification",
    "RAG citation manipulation for misinformation",
    "RAG chunking strategy exploitation technique",
    "RAG metadata injection for source confusion",
    "RAG reranking manipulation exploitation method",
    "RAG hybrid search confusion attack technique",
    "RAG grounding bypass via semantic similarity abuse",
    "RAG multi-vector retrieval manipulation attack",
])

add("Feature Flag Exploitation (12)", [
    "Feature flag override via cookie manipulation",
    "Feature flag bypass via API parameter injection",
    "Feature flag configuration exposure detection",
    "Feature flag gradual rollout targeting abuse",
    "Feature flag kill switch manipulation technique",
    "Feature flag evaluation context spoofing attack",
    "Feature flag SDK configuration interception",
    "Feature flag split test data leakage method",
    "Feature flag prerequisite chain bypass technique",
    "Feature flag segment targeting manipulation",
    "Feature flag webhook notification interception",
    "Feature flag offline mode cache poisoning attack",
])

add("A/B Test Manipulation (12)", [
    "A/B test assignment bias exploitation technique",
    "A/B test variant forcing via parameter manipulation",
    "A/B test metrics pollution exploitation method",
    "A/B test holdout group bypass technique",
    "A/B test randomization seed prediction attack",
    "A/B test exposure event manipulation method",
    "A/B test feature interaction exploitation",
    "A/B test data collection manipulation technique",
    "A/B test audience targeting bypass method",
    "A/B test statistical significance manipulation",
    "A/B test rollout percentage bypass technique",
    "A/B test experiment priority manipulation attack",
])

add("Analytics Injection Attacks (12)", [
    "Analytics event injection for data pollution",
    "Analytics pixel manipulation for tracking bypass",
    "Analytics tag manager XSS exploitation technique",
    "Analytics consent bypass via script injection",
    "Analytics user ID manipulation exploitation",
    "Analytics property injection for misattribution",
    "Analytics filter bypass via bot traffic simulation",
    "Analytics conversion hijacking exploitation",
    "Analytics session manipulation for fraud",
    "Analytics custom dimension injection attack",
    "Analytics measurement protocol abuse technique",
    "Analytics real-time data manipulation method",
])

add("Third Party Script Supply Chain (12)", [
    "Third-party script Magecart-style data skimming",
    "Third-party script formjacking exploitation",
    "Third-party CDN compromise detection technique",
    "Third-party script subresource integrity bypass",
    "Third-party tag manager injection exploitation",
    "Third-party script dependency chain attack vector",
    "Third-party script permission scope exploitation",
    "Third-party script update mechanism hijacking",
    "Third-party script sandboxing bypass technique",
    "Third-party script CSP bypass via allowed domain",
    "Third-party script data exfiltration detection",
    "Third-party script version pinning bypass attack",
])

add("npm PyPI Dependency Confusion (12)", [
    "npm dependency confusion via public package name",
    "PyPI dependency confusion via internal package name",
    "npm lifecycle script exploitation technique",
    "PyPI setup.py code execution exploitation",
    "npm scope typosquatting detection method",
    "PyPI namespace squatting exploitation technique",
    "npm install hook exploitation for RCE delivery",
    "PyPI wheel binary injection exploitation",
    "npm package.json manipulation exploitation",
    "PyPI extras_require dependency injection attack",
    "npm workspace package confusion technique",
    "PyPI requirements.txt injection exploitation",
])

add("GitHub App OAuth Exploitation (12)", [
    "GitHub App installation token privilege escalation",
    "GitHub OAuth app scope escalation exploitation",
    "GitHub App webhook secret extraction technique",
    "GitHub OAuth authorization callback manipulation",
    "GitHub App private key exposure detection method",
    "GitHub OAuth token theft via redirect manipulation",
    "GitHub App permissions escalation technique",
    "GitHub OAuth app impersonation exploitation",
    "GitHub App manifest registration manipulation",
    "GitHub OAuth device flow hijacking technique",
    "GitHub App suspended installation exploitation",
    "GitHub OAuth app consent screen manipulation",
])

print(f"After modern stack: {len(categories)} categories")

# ============ PROTOCOL (30 modules) ============

add("HTTP/2 CONTINUATION Attack (12)", [
    "HTTP/2 CONTINUATION frame flood exploitation",
    "HTTP/2 CONTINUATION header compression bomb",
    "HTTP/2 SETTINGS frame manipulation technique",
    "HTTP/2 stream priority manipulation exploitation",
    "HTTP/2 window update exhaustion attack vector",
    "HTTP/2 RST_STREAM for request cancellation abuse",
    "HTTP/2 GOAWAY frame manipulation exploitation",
    "HTTP/2 header table size manipulation technique",
    "HTTP/2 pseudo-header injection exploitation method",
    "HTTP/2 PUSH_PROMISE abuse for cache poisoning",
    "HTTP/2 stream dependency tree manipulation",
    "HTTP/2 PING frame flood denial of service",
])

add("HTTP/2 Protocol Exploitation (12)", [
    "HTTP/2 rapid reset denial of service attack",
    "HTTP/2 to HTTP/1.1 downgrade exploitation method",
    "HTTP/2 request smuggling via header injection",
    "HTTP/2 trailer header exploitation technique",
    "HTTP/2 authority pseudo-header manipulation",
    "HTTP/2 method override via pseudo-header injection",
    "HTTP/2 connection coalescing exploitation method",
    "HTTP/2 server push for cache poisoning attack",
    "HTTP/2 exclusive stream dependency abuse method",
    "HTTP/2 flow control window manipulation attack",
    "HTTP/2 huffman encoding exploitation technique",
    "HTTP/2 upgrade mechanism confusion exploitation",
])

add("HTTP/3 QUIC Security (12)", [
    "QUIC connection migration hijacking exploitation",
    "QUIC retry token manipulation attack vector",
    "QUIC 0-RTT replay attack exploitation method",
    "HTTP/3 QPACK header compression attack",
    "QUIC connection ID manipulation technique",
    "HTTP/3 stream creation exhaustion attack",
    "QUIC PATH_CHALLENGE response manipulation",
    "HTTP/3 priority signal manipulation technique",
    "QUIC version negotiation downgrade exploitation",
    "HTTP/3 server push exploitation technique",
    "QUIC amplification factor exploitation method",
    "HTTP/3 GOAWAY frame manipulation attack",
])

add("gRPC Security Deep (12)", [
    "gRPC server reflection unauthorized enumeration",
    "gRPC authentication token bypass technique",
    "gRPC deadline manipulation for timeout abuse",
    "gRPC metadata injection exploitation method",
    "gRPC streaming backpressure exploitation",
    "gRPC load balancer affinity manipulation",
    "gRPC client certificate validation bypass",
    "gRPC compression bomb denial of service",
    "gRPC retry policy exhaustion exploitation",
    "gRPC service config injection technique",
    "gRPC name resolution manipulation attack",
    "gRPC channelz endpoint information disclosure",
])

add("WebRTC Security (12)", [
    "WebRTC SRTP key extraction exploitation method",
    "WebRTC ICE candidate manipulation technique",
    "WebRTC DTLS certificate fingerprint spoofing",
    "WebRTC STUN binding request manipulation",
    "WebRTC TURN server credential brute force",
    "WebRTC data channel injection exploitation",
    "WebRTC media stream hijacking technique",
    "WebRTC SDP manipulation for call interception",
    "WebRTC IP address leak via ICE candidates",
    "WebRTC renegotiation race condition exploitation",
    "WebRTC oRTP implementation exploitation",
    "WebRTC SRTP replay attack exploitation method",
])

add("MQTT Security Exploitation (12)", [
    "MQTT authentication bypass via null credentials",
    "MQTT topic injection via wildcard subscription",
    "MQTT retained message manipulation technique",
    "MQTT will message exploitation for DoS",
    "MQTT shared subscription information theft",
    "MQTT v5 user property injection exploitation",
    "MQTT session takeover via client ID collision",
    "MQTT bridge configuration exploitation method",
    "MQTT ACL bypass via topic filter manipulation",
    "MQTT QoS exploitation for message manipulation",
    "MQTT $SYS topic information disclosure method",
    "MQTT v5 auth method bypass exploitation",
])

add("CoAP Security Exploitation (12)", [
    "CoAP observe notification spoofing technique",
    "CoAP block-wise transfer manipulation attack",
    "CoAP proxy forwarding exploitation method",
    "CoAP group communication manipulation technique",
    "CoAP token prediction exploitation attack",
    "CoAP ETag manipulation for cache confusion",
    "CoAP multicast request amplification attack",
    "CoAP DTLS session resumption bypass method",
    "CoAP resource discovery information disclosure",
    "CoAP confirmable message flood DoS attack",
    "CoAP option manipulation exploitation technique",
    "CoAP cross-protocol proxy confusion attack",
])

add("AMQP Security Exploitation (12)", [
    "AMQP virtual host unauthorized access attempt",
    "AMQP exchange binding manipulation technique",
    "AMQP queue purge exploitation for data loss",
    "AMQP consumer tag manipulation exploitation",
    "AMQP channel flow control manipulation attack",
    "AMQP header exchange routing manipulation",
    "AMQP dead letter exchange exploitation method",
    "AMQP connection blocked notification abuse",
    "AMQP publisher confirms manipulation technique",
    "AMQP message TTL manipulation exploitation",
    "AMQP queue argument injection exploitation",
    "AMQP consumer prefetch exploitation for DoS",
])

add("Protocol Buffer Exploitation (12)", [
    "Protobuf unknown field injection technique",
    "Protobuf varint overflow exploitation method",
    "Protobuf repeated field bomb denial of service",
    "Protobuf oneof field confusion exploitation",
    "Protobuf map field injection technique attack",
    "Protobuf any type URL manipulation method",
    "Protobuf extension field injection exploitation",
    "Protobuf descriptor manipulation technique",
    "Protobuf recursive message depth exploitation",
    "Protobuf service reflection information disclosure",
    "Protobuf field number collision exploitation",
    "Protobuf default value confusion exploitation",
])

add("MessagePack Injection (12)", [
    "MessagePack type confusion exploitation method",
    "MessagePack deserialization exploitation technique",
    "MessagePack ext type abuse exploitation vector",
    "MessagePack bin type injection for RCE delivery",
    "MessagePack timestamp extension manipulation",
    "MessagePack nested object depth exploitation",
    "MessagePack integer overflow exploitation method",
    "MessagePack map size manipulation technique",
    "MessagePack string length overflow exploitation",
    "MessagePack fixarray overflow exploitation",
    "MessagePack nil value injection exploitation",
    "MessagePack custom extension handler exploitation",
])

add("Thrift Protocol Exploitation (12)", [
    "Thrift TBinaryProtocol exploitation technique",
    "Thrift TCompactProtocol manipulation method",
    "Thrift multiplexed service confusion attack",
    "Thrift TSSLSocket certificate validation bypass",
    "Thrift struct field injection exploitation",
    "Thrift union type confusion exploitation method",
    "Thrift recursive struct exploitation technique",
    "Thrift exception message information disclosure",
    "Thrift oneway method abuse for fire-and-forget",
    "Thrift container overflow exploitation method",
    "Thrift service discovery exploitation technique",
    "Thrift processor chain manipulation exploitation",
])

add("Apache Kafka Protocol (12)", [
    "Kafka producer authentication bypass technique",
    "Kafka consumer group coordinator manipulation",
    "Kafka transaction ID collision exploitation",
    "Kafka offset manipulation for data replay",
    "Kafka partition assignment manipulation attack",
    "Kafka quota exhaustion denial of service",
    "Kafka delegation token exploitation technique",
    "Kafka ACL evaluation order bypass method",
    "Kafka controller epoch manipulation attack",
    "Kafka log compaction exploitation technique",
    "Kafka ISR manipulation for data loss attack",
    "Kafka client ID spoofing exploitation method",
])

add("Redis Protocol Exploitation (12)", [
    "Redis RESP protocol injection exploitation",
    "Redis inline command injection technique",
    "Redis Lua script sandbox escape exploitation",
    "Redis module command injection exploitation",
    "Redis cluster bus protocol manipulation",
    "Redis sentinel failover manipulation attack",
    "Redis stream consumer group manipulation",
    "Redis keyspace notification exploitation",
    "Redis pub/sub pattern injection technique",
    "Redis transaction MULTI/EXEC manipulation",
    "Redis blocking command resource exhaustion",
    "Redis OBJECT command information disclosure",
])

add("Memcached Protocol Exploitation (12)", [
    "Memcached binary protocol header manipulation",
    "Memcached UDP amplification exploitation method",
    "Memcached SASL authentication bypass technique",
    "Memcached slab class manipulation exploitation",
    "Memcached stats command information disclosure",
    "Memcached flush_all denial of service method",
    "Memcached CAS token prediction exploitation",
    "Memcached connection limit exhaustion attack",
    "Memcached key enumeration via stats cachedump",
    "Memcached multiget command resource exhaustion",
    "Memcached value serialization exploitation",
    "Memcached protocol version confusion attack",
])

add("MongoDB Wire Protocol (12)", [
    "MongoDB wire protocol OP_MSG manipulation",
    "MongoDB authentication mechanism downgrade",
    "MongoDB cursor manipulation exploitation",
    "MongoDB exhaust flag resource exhaustion",
    "MongoDB getMore command manipulation technique",
    "MongoDB aggregate pipeline injection attack",
    "MongoDB change stream exploitation technique",
    "MongoDB transaction manipulation exploitation",
    "MongoDB collation exploitation technique",
    "MongoDB compressor manipulation exploitation",
    "MongoDB session pool manipulation technique",
    "MongoDB hello command information disclosure",
])

add("PostgreSQL Wire Protocol (12)", [
    "PostgreSQL StartupMessage manipulation technique",
    "PostgreSQL COPY command exploitation method",
    "PostgreSQL prepared statement confusion attack",
    "PostgreSQL notification channel exploitation",
    "PostgreSQL large object exploitation technique",
    "PostgreSQL replication protocol manipulation",
    "PostgreSQL row description manipulation attack",
    "PostgreSQL SCRAM authentication downgrade",
    "PostgreSQL function call protocol exploitation",
    "PostgreSQL CancelRequest exploitation method",
    "PostgreSQL parameter status information leak",
    "PostgreSQL error response information disclosure",
])

add("MySQL Protocol Exploitation (12)", [
    "MySQL authentication plugin manipulation",
    "MySQL COM_QUERY injection via binary protocol",
    "MySQL prepared statement re-execution attack",
    "MySQL local infile exploitation technique",
    "MySQL multi-statement execution exploitation",
    "MySQL change user command exploitation method",
    "MySQL binlog manipulation exploitation technique",
    "MySQL connection attribute information leak",
    "MySQL X Protocol exploitation technique",
    "MySQL compression protocol manipulation attack",
    "MySQL SHA2 authentication downgrade technique",
    "MySQL server greeting manipulation exploitation",
])

print(f"After protocol: {len(categories)} categories")

# ============ MOBILE & CLIENT (30 modules) ============

add("Android Intent Exploitation (12)", [
    "Android intent hijacking via exported activity",
    "Android intent redirection exploitation technique",
    "Android pending intent manipulation attack",
    "Android implicit intent interception method",
    "Android intent filter priority manipulation",
    "Android deep link validation bypass technique",
    "Android intent extra data injection exploitation",
    "Android broadcast intent spoofing attack",
    "Android activity task affinity manipulation",
    "Android intent selector injection technique",
    "Android custom permission exploitation method",
    "Android intent URI scheme manipulation attack",
])

add("Android Provider Broadcast (12)", [
    "Android content provider SQL injection attack",
    "Android content provider path traversal method",
    "Android broadcast receiver exploitation technique",
    "Android file provider misconfiguration exploitation",
    "Android content provider permission bypass",
    "Android ordered broadcast manipulation attack",
    "Android content provider URI manipulation",
    "Android sticky broadcast exploitation technique",
    "Android content provider cursor manipulation",
    "Android local broadcast interception method",
    "Android content provider grant URI permission abuse",
    "Android broadcast receiver priority manipulation",
])

add("iOS URL Scheme Exploitation (12)", [
    "iOS URL scheme hijacking exploitation technique",
    "iOS universal link validation bypass method",
    "iOS keychain access group exploitation attack",
    "iOS custom URL scheme parameter injection",
    "iOS deep link redirect manipulation technique",
    "iOS associated domains manipulation method",
    "iOS URL scheme race condition exploitation",
    "iOS keychain item accessibility exploitation",
    "iOS universal link app-site-association bypass",
    "iOS URL scheme data exfiltration technique",
    "iOS keychain sharing exploitation method",
    "iOS handoff continuation exploitation attack",
])

add("React Native Security (12)", [
    "React Native bridge injection exploitation",
    "React Native JS bundle manipulation technique",
    "React Native AsyncStorage data extraction",
    "React Native deep linking exploitation method",
    "React Native hermes bytecode manipulation",
    "React Native native module exploitation attack",
    "React Native code push update manipulation",
    "React Native debug bridge exploitation method",
    "React Native biometric bypass exploitation",
    "React Native certificate pinning bypass method",
    "React Native WebView bridge exploitation",
    "React Native Metro bundler exploitation attack",
])

add("Flutter Security Issues (12)", [
    "Flutter platform channel exploitation technique",
    "Flutter AOT compiled code analysis method",
    "Flutter shared preferences data extraction",
    "Flutter deep link handling exploitation attack",
    "Flutter method channel injection technique",
    "Flutter plugin exploitation for privilege access",
    "Flutter web rendering exploitation method",
    "Flutter isolate communication manipulation",
    "Flutter asset bundle extraction technique",
    "Flutter obfuscation bypass for reverse engineering",
    "Flutter Firebase integration exploitation",
    "Flutter custom engine exploitation technique",
])

add("Capacitor Cordova Security (12)", [
    "Capacitor plugin bridge exploitation technique",
    "Cordova whitelist bypass exploitation method",
    "Capacitor native HTTP bypass exploitation",
    "Cordova file system access exploitation attack",
    "Capacitor local notification manipulation",
    "Cordova InAppBrowser exploitation technique",
    "Capacitor live update manipulation method",
    "Cordova camera plugin exploitation technique",
    "Capacitor Filesystem API path traversal",
    "Cordova network information leakage method",
    "Capacitor keyboard plugin exploitation",
    "Cordova device plugin information disclosure",
])

add("PWA Security Exploitation (12)", [
    "PWA manifest manipulation for phishing attack",
    "PWA service worker scope hijacking technique",
    "PWA offline cache poisoning exploitation method",
    "PWA install prompt manipulation technique",
    "PWA push subscription hijacking exploitation",
    "PWA background sync data exfiltration attack",
    "PWA share target manipulation exploitation",
    "PWA shortcut injection for phishing technique",
    "PWA screenshot manipulation for app store",
    "PWA launch handler exploitation technique",
    "PWA file handler registration exploitation",
    "PWA protocol handler manipulation attack",
])

add("Electron App Security (12)", [
    "Electron nodeIntegration exploitation technique",
    "Electron contextBridge bypass exploitation method",
    "Electron remote module exploitation attack",
    "Electron preload script injection technique",
    "Electron protocol handler exploitation method",
    "Electron webContents manipulation exploitation",
    "Electron IPC message interception technique",
    "Electron shell.openExternal exploitation attack",
    "Electron custom protocol scheme exploitation",
    "Electron sandbox bypass exploitation technique",
    "Electron fuses manipulation exploitation method",
    "Electron auto-update manipulation exploitation",
])

add("Chrome Extension Security (12)", [
    "Chrome extension content script injection attack",
    "Chrome extension message passing exploitation",
    "Chrome extension permissions escalation technique",
    "Chrome extension background page exploitation",
    "Chrome extension web accessible resources abuse",
    "Chrome extension storage data extraction method",
    "Chrome extension manifest V3 bypass technique",
    "Chrome extension native messaging exploitation",
    "Chrome extension declarativeNetRequest manipulation",
    "Chrome extension service worker exploitation",
    "Chrome extension cross-origin isolation bypass",
    "Chrome extension CSP bypass exploitation method",
])

add("Browser Extension Exploitation (12)", [
    "Browser extension Universal XSS via content script",
    "Browser extension clickjacking exploitation method",
    "Browser extension authentication credential theft",
    "Browser extension session token exfiltration",
    "Browser extension DOM manipulation exploitation",
    "Browser extension network request interception",
    "Browser extension clipboard access exploitation",
    "Browser extension geolocation spoofing method",
    "Browser extension camera microphone access abuse",
    "Browser extension download manipulation technique",
    "Browser extension tab capture exploitation method",
    "Browser extension debugger API exploitation attack",
])

add("WebView Exploitation Techniques (12)", [
    "WebView JavaScript bridge exploitation method",
    "WebView file scheme access exploitation attack",
    "WebView intent scheme exploitation technique",
    "WebView SSL error handling bypass exploitation",
    "WebView cookie manipulation exploitation method",
    "WebView mixed content exploitation technique",
    "WebView evaluateJavascript injection attack",
    "WebView download handler exploitation method",
    "WebView postMessage exploitation technique",
    "WebView navigation override exploitation attack",
    "WebView WebSettings manipulation technique",
    "WebView renderer process exploitation method",
])

add("Mobile API Security Advanced (12)", [
    "Mobile API certificate pinning bypass technique",
    "Mobile API token storage extraction method",
    "Mobile API request signing bypass exploitation",
    "Mobile API device attestation bypass technique",
    "Mobile API biometric authentication bypass",
    "Mobile API screenshot prevention bypass method",
    "Mobile API root detection bypass technique",
    "Mobile API debug detection bypass exploitation",
    "Mobile API anti-tampering bypass method",
    "Mobile API obfuscation reversal technique",
    "Mobile API dynamic analysis detection bypass",
    "Mobile API frida detection bypass exploitation",
])

add("Mobile Certificate Pinning Bypass (12)", [
    "SSL pinning bypass via Frida hook technique",
    "SSL pinning bypass via Objection framework",
    "SSL pinning bypass via network security config",
    "SSL pinning bypass via custom TrustManager",
    "SSL pinning bypass via proxy certificate injection",
    "SSL pinning bypass via binary patching technique",
    "SSL pinning bypass via Xposed module exploitation",
    "SSL pinning bypass via Substrate framework",
    "SSL pinning bypass via MITM proxy configuration",
    "SSL pinning bypass via certificate transparency log",
    "SSL pinning bypass via shared library hooking",
    "SSL pinning bypass via runtime class replacement",
])

add("Mobile Binary Analysis (12)", [
    "Mobile binary string extraction for secrets",
    "Mobile binary symbol analysis for API discovery",
    "Mobile binary native library exploitation",
    "Mobile binary anti-debug bypass technique",
    "Mobile binary integrity check bypass method",
    "Mobile binary encryption key extraction",
    "Mobile binary obfuscation reversal technique",
    "Mobile binary hardcoded credential discovery",
    "Mobile binary API endpoint extraction method",
    "Mobile binary resource file analysis technique",
    "Mobile binary third-party SDK identification",
    "Mobile binary dynamic library injection attack",
])

add("Mobile Local Storage (12)", [
    "Mobile SQLite database extraction technique",
    "Mobile shared preferences sensitive data exposure",
    "Mobile keychain keystore data extraction method",
    "Mobile internal storage file access exploitation",
    "Mobile cache data extraction technique",
    "Mobile backup data extraction exploitation method",
    "Mobile clipboard data interception technique",
    "Mobile screenshot cache data extraction",
    "Mobile log file sensitive data exposure",
    "Mobile cookie storage data extraction technique",
    "Mobile WebView local storage data access",
    "Mobile realm database extraction exploitation",
])

add("Mobile IPC Exploitation (12)", [
    "Mobile inter-process communication interception",
    "Mobile bound service exploitation technique",
    "Mobile messenger handler exploitation method",
    "Mobile AIDL interface exploitation technique",
    "Mobile Binder transaction manipulation attack",
    "Mobile notification listener exploitation method",
    "Mobile accessibility service abuse technique",
    "Mobile JobScheduler exploitation method",
    "Mobile WorkManager manipulation exploitation",
    "Mobile AccountManager exploitation technique",
    "Mobile ContentProvider IPC exploitation method",
    "Mobile custom permission enforcement bypass",
])

# ============ COMPLIANCE & PRIVACY (25 modules) ============

add("GDPR Data Subject Rights (12)", [
    "GDPR right to access request bypass detection",
    "GDPR data portability format compliance check",
    "GDPR right to rectification enforcement testing",
    "GDPR purpose limitation violation detection",
    "GDPR lawful basis documentation compliance",
    "GDPR data protection impact assessment check",
    "GDPR automated decision-making disclosure test",
    "GDPR controller processor agreement compliance",
    "GDPR cross-border transfer safeguards testing",
    "GDPR data breach notification compliance check",
    "GDPR special category data processing test",
    "GDPR joint controller arrangement compliance",
])

add("PCI DSS Compliance Checks (12)", [
    "PCI DSS cardholder data exposure detection",
    "PCI DSS encryption in transit compliance test",
    "PCI DSS encryption at rest compliance check",
    "PCI DSS network segmentation validation test",
    "PCI DSS access control requirement compliance",
    "PCI DSS vulnerability management compliance",
    "PCI DSS logging and monitoring compliance check",
    "PCI DSS authentication requirement validation",
    "PCI DSS payment page integrity monitoring",
    "PCI DSS third-party service provider assessment",
    "PCI DSS wireless network security compliance",
    "PCI DSS key management compliance validation",
])

add("HIPAA PHI Exposure Detection (12)", [
    "HIPAA PHI exposure in API response detection",
    "HIPAA minimum necessary rule compliance test",
    "HIPAA access control requirement validation",
    "HIPAA audit trail compliance verification",
    "HIPAA encryption requirement compliance check",
    "HIPAA unique user identification compliance",
    "HIPAA automatic logoff compliance verification",
    "HIPAA integrity control compliance testing",
    "HIPAA transmission security compliance check",
    "HIPAA business associate agreement compliance",
    "HIPAA breach notification compliance testing",
    "HIPAA de-identification requirement validation",
])

add("SOX Compliance Testing (12)", [
    "SOX financial data access control validation",
    "SOX audit trail integrity compliance check",
    "SOX change management process compliance test",
    "SOX segregation of duties enforcement testing",
    "SOX IT general controls compliance validation",
    "SOX application control testing compliance",
    "SOX data backup and recovery compliance check",
    "SOX access provisioning process compliance",
    "SOX security monitoring compliance validation",
    "SOX incident response compliance testing",
    "SOX vendor management compliance verification",
    "SOX encryption requirement compliance check",
])

add("CCPA Privacy Rights Testing (12)", [
    "CCPA right to know data collection disclosure",
    "CCPA opt-out mechanism compliance validation",
    "CCPA data deletion request compliance check",
    "CCPA do not sell my info compliance test",
    "CCPA financial incentive disclosure compliance",
    "CCPA authorized agent request compliance",
    "CCPA data category disclosure compliance test",
    "CCPA third-party sharing disclosure compliance",
    "CCPA minors consent requirement compliance",
    "CCPA response timing compliance validation",
    "CCPA non-discrimination compliance testing",
    "CCPA service provider contract compliance",
])

add("LGPD Brazil Compliance (12)", [
    "LGPD data processing legal basis compliance",
    "LGPD data subject consent requirement testing",
    "LGPD data protection officer requirement check",
    "LGPD international transfer compliance testing",
    "LGPD data breach reporting compliance check",
    "LGPD privacy impact assessment compliance",
    "LGPD data minimization compliance verification",
    "LGPD purpose limitation compliance testing",
    "LGPD data subject rights enforcement check",
    "LGPD sensitive data processing compliance",
    "LGPD automated decision transparency testing",
    "LGPD data retention period compliance check",
])

add("Cookie Law Enforcement (12)", [
    "Cookie consent banner implementation compliance",
    "Cookie categorization accuracy verification",
    "Cookie consent prior to processing compliance",
    "Cookie consent withdrawal mechanism testing",
    "Cookie third-party tracking compliance check",
    "Cookie consent record keeping compliance",
    "Cookie necessary cookies exemption validation",
    "Cookie analytics consent requirement testing",
    "Cookie marketing consent requirement check",
    "Cookie preference center implementation test",
    "Cookie cross-domain consent compliance check",
    "Cookie consent renewal requirement testing",
])

add("Data Retention Testing (12)", [
    "Data retention policy enforcement verification",
    "Data retention period compliance validation",
    "Data retention automated deletion testing",
    "Data retention backup purge compliance check",
    "Data retention log file compliance testing",
    "Data retention cache data compliance check",
    "Data retention database archival compliance",
    "Data retention analytics data compliance test",
    "Data retention email data compliance check",
    "Data retention third-party data compliance",
    "Data retention metadata compliance testing",
    "Data retention temporary file cleanup check",
])

add("Right to Erasure Verification (12)", [
    "Erasure request processing compliance test",
    "Erasure completeness verification in database",
    "Erasure from backup systems compliance check",
    "Erasure from search index compliance testing",
    "Erasure from cache systems verification test",
    "Erasure from analytics systems compliance",
    "Erasure from third-party systems verification",
    "Erasure from log files compliance testing",
    "Erasure notification to processors compliance",
    "Erasure exception handling compliance check",
    "Erasure verification response compliance test",
    "Erasure from derived data compliance check",
])

add("Consent Management Bypass (12)", [
    "Consent management platform bypass technique",
    "Consent manipulation via cookie injection",
    "Consent dark pattern detection testing",
    "Consent revocation enforcement verification",
    "Consent granularity compliance testing",
    "Consent mechanism accessibility compliance",
    "Consent record integrity verification test",
    "Consent propagation to third parties check",
    "Consent version tracking compliance test",
    "Consent collection timing compliance check",
    "Consent wall detection and compliance test",
    "Consent bundling prohibition compliance",
])

add("Privacy Policy Compliance (12)", [
    "Privacy policy data collection accuracy test",
    "Privacy policy third-party disclosure compliance",
    "Privacy policy update notification compliance",
    "Privacy policy accessibility compliance check",
    "Privacy policy contact information compliance",
    "Privacy policy retention period disclosure test",
    "Privacy policy rights exercise information",
    "Privacy policy language clarity compliance",
    "Privacy policy cookie usage disclosure test",
    "Privacy policy data transfer disclosure check",
    "Privacy policy security measures disclosure",
    "Privacy policy automated processing disclosure",
])

add("Data Minimization Compliance (12)", [
    "Data minimization in form field collection test",
    "Data minimization in API request parameters",
    "Data minimization in logging practices check",
    "Data minimization in analytics collection test",
    "Data minimization in third-party sharing check",
    "Data minimization in data storage practices",
    "Data minimization in registration process test",
    "Data minimization in payment processing check",
    "Data minimization in profile data collection",
    "Data minimization in search functionality test",
    "Data minimization in notification content check",
    "Data minimization in export functionality test",
])

add("Cross Border Transfer Detection (12)", [
    "Cross-border data transfer mechanism compliance",
    "Cross-border transfer safeguard adequacy test",
    "Cross-border transfer to third countries check",
    "Cross-border transfer documentation compliance",
    "Cross-border transfer via cloud services test",
    "Cross-border transfer via CDN routing check",
    "Cross-border transfer via analytics services",
    "Cross-border transfer via email services test",
    "Cross-border transfer via payment processors",
    "Cross-border transfer notification compliance",
    "Cross-border transfer impact assessment check",
    "Cross-border transfer standard clause compliance",
])

print(f"After mobile/compliance: {len(categories)} categories")

# ============ CMS & FRAMEWORK SPECIFIC (50 modules) ============

add("WordPress REST API Deep (12)", [
    "WordPress REST API user enumeration technique",
    "WordPress REST API post content exposure",
    "WordPress REST API authentication bypass method",
    "WordPress REST API privilege escalation attack",
    "WordPress REST API media upload exploitation",
    "WordPress REST API search injection technique",
    "WordPress REST API batch endpoint exploitation",
    "WordPress REST API custom endpoint discovery",
    "WordPress REST API nonce bypass technique",
    "WordPress REST API taxonomy manipulation attack",
    "WordPress REST API block rendering exploitation",
    "WordPress REST API settings exposure method",
])

add("WordPress Plugin Exploitation Part1 (12)", [
    "WordPress Elementor RCE exploitation technique",
    "WordPress WPForms file upload exploitation",
    "WordPress Yoast SEO sitemap injection attack",
    "WordPress WooCommerce payment bypass technique",
    "WordPress Contact Form 7 file upload exploit",
    "WordPress Wordfence bypass exploitation method",
    "WordPress Jetpack SSRF exploitation technique",
    "WordPress All-in-One SEO injection attack",
    "WordPress UpdraftPlus backup exposure method",
    "WordPress WP Mail SMTP credential exposure",
    "WordPress Duplicate Post privilege escalation",
    "WordPress Classic Editor stored XSS technique",
])

add("WordPress Plugin Exploitation Part2 (12)", [
    "WordPress Advanced Custom Fields injection",
    "WordPress Gravity Forms file upload exploitation",
    "WordPress Rank Math SEO manipulation attack",
    "WordPress TablePress SQL injection technique",
    "WordPress Smush image processing exploitation",
    "WordPress Redirection plugin open redirect abuse",
    "WordPress MonsterInsights analytics manipulation",
    "WordPress LiteSpeed Cache poisoning technique",
    "WordPress EWWW Image Optimizer exploitation",
    "WordPress Really Simple SSL bypass technique",
    "WordPress Limit Login Attempts bypass method",
    "WordPress Insert Headers Footers XSS technique",
])

add("WordPress Plugin Exploitation Part3 (12)", [
    "WordPress WP Super Cache poisoning technique",
    "WordPress W3 Total Cache exploitation method",
    "WordPress Akismet data exposure technique",
    "WordPress BBPress forum injection exploitation",
    "WordPress BuddyPress profile exploitation",
    "WordPress Easy Digital Downloads bypass method",
    "WordPress MemberPress access bypass technique",
    "WordPress LearnDash course access exploitation",
    "WordPress Beaver Builder stored XSS attack",
    "WordPress Divi Builder exploitation technique",
    "WordPress Brizy Builder file upload exploitation",
    "WordPress Oxygen Builder RCE exploitation method",
])

add("WordPress Plugin Exploitation Part4 (12)", [
    "WordPress WP Rocket cache exploitation technique",
    "WordPress Sucuri plugin bypass method",
    "WordPress iThemes Security bypass exploitation",
    "WordPress BackWPup backup exposure method",
    "WordPress MailChimp integration exploitation",
    "WordPress OptinMonster DOM manipulation attack",
    "WordPress SeedProd maintenance bypass technique",
    "WordPress Coming Soon Page bypass exploitation",
    "WordPress Under Construction bypass method",
    "WordPress Login Lockdown bypass technique",
    "WordPress Two Factor bypass exploitation method",
    "WordPress Disable Comments exploitation technique",
])

add("Joomla Exploitation (12)", [
    "Joomla com_fields SQL injection exploitation",
    "Joomla user registration privilege escalation",
    "Joomla template file upload exploitation",
    "Joomla REST API information disclosure",
    "Joomla media manager path traversal attack",
    "Joomla configuration.php exposure detection",
    "Joomla extension installation exploitation",
    "Joomla search component injection technique",
    "Joomla session fixation exploitation method",
    "Joomla LDAP authentication bypass technique",
    "Joomla weblinks redirect exploitation method",
    "Joomla category ACL bypass exploitation attack",
])

add("Drupal Exploitation (12)", [
    "Drupal Drupalgeddon2 RCE detection technique",
    "Drupal access bypass via route manipulation",
    "Drupal render array exploitation technique",
    "Drupal AJAX API exploitation for RCE",
    "Drupal file upload restriction bypass method",
    "Drupal views module SQL injection technique",
    "Drupal RESTful API authentication bypass",
    "Drupal CSRF token bypass exploitation method",
    "Drupal configuration export exposure detection",
    "Drupal module installation exploitation attack",
    "Drupal twig template injection exploitation",
    "Drupal user enumeration via password reset",
])

add("Magento Security (12)", [
    "Magento admin panel brute force exploitation",
    "Magento API authentication bypass technique",
    "Magento customer data exposure exploitation",
    "Magento payment gateway bypass method",
    "Magento file manager path traversal attack",
    "Magento template injection exploitation method",
    "Magento CSRF token bypass exploitation technique",
    "Magento widget directive injection attack",
    "Magento module installation exploitation",
    "Magento customer group privilege escalation",
    "Magento quote manipulation exploitation method",
    "Magento cache invalidation exploitation technique",
])

add("Shopify Security (12)", [
    "Shopify app OAuth scope escalation exploitation",
    "Shopify Liquid template injection technique",
    "Shopify checkout manipulation exploitation",
    "Shopify discount code brute force technique",
    "Shopify API rate limit bypass exploitation",
    "Shopify webhook manipulation exploitation",
    "Shopify storefront API data exposure method",
    "Shopify admin API privilege escalation attack",
    "Shopify script tag injection exploitation",
    "Shopify app proxy SSRF exploitation technique",
    "Shopify metafield data exposure method",
    "Shopify multipass token manipulation attack",
])

add("WooCommerce Security (12)", [
    "WooCommerce payment gateway bypass technique",
    "WooCommerce coupon manipulation exploitation",
    "WooCommerce order status manipulation attack",
    "WooCommerce REST API authentication bypass",
    "WooCommerce price manipulation exploitation",
    "WooCommerce stock manipulation technique",
    "WooCommerce shipping address manipulation",
    "WooCommerce tax calculation bypass exploitation",
    "WooCommerce downloadable product access bypass",
    "WooCommerce subscription manipulation attack",
    "WooCommerce webhook data exposure technique",
    "WooCommerce customer data export exploitation",
])

add("PrestaShop Security (12)", [
    "PrestaShop SQL injection in module parameter",
    "PrestaShop file upload exploitation technique",
    "PrestaShop admin authentication bypass method",
    "PrestaShop webservice API exploitation attack",
    "PrestaShop template injection exploitation",
    "PrestaShop customer data exposure technique",
    "PrestaShop payment module bypass exploitation",
    "PrestaShop cart manipulation exploitation",
    "PrestaShop module installation exploitation",
    "PrestaShop CSRF token bypass technique",
    "PrestaShop cache poisoning exploitation method",
    "PrestaShop SEO injection exploitation technique",
])

add("Moodle Security (12)", [
    "Moodle course enrollment bypass exploitation",
    "Moodle quiz grade manipulation technique",
    "Moodle file upload path traversal attack",
    "Moodle web service API exploitation method",
    "Moodle role assignment exploitation technique",
    "Moodle assignment submission manipulation",
    "Moodle messaging system exploitation attack",
    "Moodle calendar event injection technique",
    "Moodle badge criteria manipulation method",
    "Moodle external tool configuration exposure",
    "Moodle repository file access exploitation",
    "Moodle cohort data exposure exploitation",
])

add("Confluence Jira Exploitation (12)", [
    "Confluence OGNL injection exploitation technique",
    "Confluence space permission bypass exploitation",
    "Jira workflow transition manipulation attack",
    "Confluence macro code execution exploitation",
    "Jira custom field injection exploitation",
    "Confluence user macro XSS exploitation method",
    "Jira project permission bypass technique",
    "Confluence attachment exploitation method",
    "Jira bulk operation exploitation technique",
    "Confluence REST API privilege escalation",
    "Jira Velocity template injection exploitation",
    "Confluence widget connector SSRF exploitation",
])

add("SharePoint Exploitation (12)", [
    "SharePoint deserialization exploitation technique",
    "SharePoint page creation XSS exploitation",
    "SharePoint workflow exploitation method",
    "SharePoint API authentication bypass technique",
    "SharePoint file sharing permission exploitation",
    "SharePoint search query injection technique",
    "SharePoint web part exploitation method",
    "SharePoint site collection permission bypass",
    "SharePoint managed metadata manipulation",
    "SharePoint list view threshold exploitation",
    "SharePoint external sharing exploitation",
    "SharePoint app catalog exploitation technique",
])

add("Salesforce Misconfiguration (12)", [
    "Salesforce community site data exposure",
    "Salesforce API permission misconfiguration",
    "Salesforce Lightning component exploitation",
    "Salesforce Flow process manipulation attack",
    "Salesforce object-level security bypass",
    "Salesforce field-level security bypass method",
    "Salesforce Apex trigger manipulation technique",
    "Salesforce Visualforce page injection attack",
    "Salesforce sharing rules bypass exploitation",
    "Salesforce connected app exploitation method",
    "Salesforce SOQL injection exploitation technique",
    "Salesforce metadata API exposure exploitation",
])

add("HubSpot Security (12)", [
    "HubSpot private app token exposure detection",
    "HubSpot CMS template injection exploitation",
    "HubSpot workflow automation manipulation",
    "HubSpot form submission manipulation technique",
    "HubSpot API scope escalation exploitation",
    "HubSpot OAuth application exploitation method",
    "HubSpot CRM data exposure exploitation",
    "HubSpot email template injection technique",
    "HubSpot webhook manipulation exploitation",
    "HubSpot custom object permission bypass",
    "HubSpot serverless function exploitation",
    "HubSpot tracking code manipulation technique",
])

add("Zendesk Exploitation (12)", [
    "Zendesk ticket data exposure exploitation",
    "Zendesk API authentication bypass technique",
    "Zendesk webhook manipulation exploitation",
    "Zendesk custom app exploitation method",
    "Zendesk agent impersonation exploitation",
    "Zendesk help center content injection attack",
    "Zendesk automation rule manipulation technique",
    "Zendesk OAuth token exploitation method",
    "Zendesk attachment data exposure technique",
    "Zendesk SLA policy manipulation exploitation",
    "Zendesk macro injection exploitation attack",
    "Zendesk custom field injection technique",
])

add("ServiceNow Exploitation (12)", [
    "ServiceNow ACL bypass exploitation technique",
    "ServiceNow script include exploitation method",
    "ServiceNow Glide record injection attack",
    "ServiceNow REST API authentication bypass",
    "ServiceNow workflow exploitation technique",
    "ServiceNow service portal exploitation method",
    "ServiceNow client script injection attack",
    "ServiceNow transform map exploitation technique",
    "ServiceNow scheduled job manipulation method",
    "ServiceNow mid server exploitation technique",
    "ServiceNow OAuth provider exploitation attack",
    "ServiceNow scoped application exploitation",
])

add("SAP Security Exploitation (12)", [
    "SAP RFC gateway exploitation technique",
    "SAP ICM handler exploitation method",
    "SAP Solution Manager exploitation attack",
    "SAP HANA database exploitation technique",
    "SAP GUI session hijacking method",
    "SAP web dispatcher exploitation technique",
    "SAP message server exploitation method",
    "SAP Fiori application exploitation attack",
    "SAP BW report data exposure technique",
    "SAP transport request manipulation method",
    "SAP authorization object bypass technique",
    "SAP CRM web service exploitation attack",
])

add("Oracle EBS Security (12)", [
    "Oracle EBS SQL injection in concurrent program",
    "Oracle EBS authentication bypass technique",
    "Oracle EBS workflow notification exploitation",
    "Oracle EBS form function exploitation method",
    "Oracle EBS responsibility escalation attack",
    "Oracle EBS FNDCPASS utility exploitation",
    "Oracle EBS XML Publisher exploitation technique",
    "Oracle EBS OAF page exploitation method",
    "Oracle EBS apps password exposure technique",
    "Oracle EBS diagnostic servlets exploitation",
    "Oracle EBS AME rule manipulation exploitation",
    "Oracle EBS iExpense exploitation technique",
])

add("VMware vCenter Exploitation (12)", [
    "VMware vCenter Log4Shell exploitation technique",
    "VMware vCenter SSRF exploitation method",
    "VMware vCenter authentication bypass attack",
    "VMware vCenter file upload exploitation technique",
    "VMware vCenter SOAP API exploitation method",
    "VMware vCenter virtual machine escape technique",
    "VMware vCenter VMDK file access exploitation",
    "VMware vCenter service endpoint enumeration",
    "VMware vCenter SAML assertion manipulation",
    "VMware vCenter database credential exposure",
    "VMware vCenter plugin exploitation technique",
    "VMware vCenter ESXi host exploitation method",
])

add("Citrix ADC Gateway (12)", [
    "Citrix ADC path traversal exploitation technique",
    "Citrix Gateway authentication bypass method",
    "Citrix ADC SSRF exploitation technique",
    "Citrix Gateway session riding exploitation",
    "Citrix ADC configuration exposure detection",
    "Citrix Gateway credential harvesting technique",
    "Citrix ADC virtual server exploitation method",
    "Citrix Gateway authorization bypass technique",
    "Citrix ADC WAF bypass exploitation method",
    "Citrix Gateway SAML manipulation technique",
    "Citrix ADC management interface exploitation",
    "Citrix Gateway StoreFront exploitation attack",
])

add("Fortinet FortiGate (12)", [
    "FortiGate SSL VPN exploitation technique",
    "FortiGate management interface exposure method",
    "FortiGate authentication bypass exploitation",
    "FortiGate firewall policy bypass technique",
    "FortiGate SSLVPN credential harvesting",
    "FortiGate REST API exploitation method",
    "FortiGate FortiManager exploitation technique",
    "FortiGate SD-WAN manipulation exploitation",
    "FortiGate log data exposure technique",
    "FortiGate certificate manipulation method",
    "FortiGate web filter bypass exploitation",
    "FortiGate IPS bypass exploitation technique",
])

add("Palo Alto PAN-OS (12)", [
    "PAN-OS GlobalProtect exploitation technique",
    "PAN-OS management interface exposure method",
    "PAN-OS authentication bypass exploitation",
    "PAN-OS XML API exploitation technique",
    "PAN-OS configuration exposure detection",
    "PAN-OS Panorama exploitation method",
    "PAN-OS URL filtering bypass technique",
    "PAN-OS WildFire evasion exploitation method",
    "PAN-OS User-ID agent exploitation technique",
    "PAN-OS SSL decryption bypass method",
    "PAN-OS zone-based policy bypass exploitation",
    "PAN-OS log forwarding credential exposure",
])

add("SonicWall Exploitation (12)", [
    "SonicWall SMA path traversal exploitation",
    "SonicWall SSL VPN authentication bypass",
    "SonicWall firmware update manipulation",
    "SonicWall management interface exploitation",
    "SonicWall virtual office exploitation technique",
    "SonicWall content filtering bypass method",
    "SonicWall VPN credential harvesting technique",
    "SonicWall REST API exploitation method",
    "SonicWall access rule bypass exploitation",
    "SonicWall WAF bypass exploitation technique",
    "SonicWall capture ATP evasion technique",
    "SonicWall backup configuration exposure",
])

add("F5 BIG-IP Exploitation (12)", [
    "F5 BIG-IP iControl REST exploitation technique",
    "F5 BIG-IP TMUI authentication bypass method",
    "F5 BIG-IP cookie decoding exploitation technique",
    "F5 BIG-IP iRule exploitation for traffic hijacking",
    "F5 BIG-IP configuration exposure detection",
    "F5 BIG-IP SSRF via management interface",
    "F5 BIG-IP virtual server enumeration technique",
    "F5 BIG-IP persistence cookie manipulation",
    "F5 BIG-IP ASM WAF bypass exploitation",
    "F5 BIG-IP pool member discovery technique",
    "F5 BIG-IP SSL profile manipulation exploitation",
    "F5 BIG-IP health monitor exploitation method",
])

add("Ivanti Pulse Secure (12)", [
    "Ivanti Connect Secure authentication bypass",
    "Ivanti EPMM exploitation technique",
    "Pulse Secure VPN file read exploitation",
    "Ivanti Sentry API exploitation method",
    "Pulse Secure admin interface exploitation",
    "Ivanti ITSM exploitation technique",
    "Pulse Secure session replay exploitation",
    "Ivanti Neurons exploitation method",
    "Pulse Secure meeting exploitation technique",
    "Ivanti Workspace Control exploitation",
    "Pulse Secure host checker bypass technique",
    "Ivanti Avalanche exploitation method",
])

add("Cisco ASA IOS (12)", [
    "Cisco ASA WebVPN exploitation technique",
    "Cisco ASA SNMP community string exploitation",
    "Cisco IOS Smart Install exploitation method",
    "Cisco ASA AnyConnect exploitation technique",
    "Cisco IOS HTTP server exploitation method",
    "Cisco ASA REST API exploitation technique",
    "Cisco IOS OSPF manipulation exploitation",
    "Cisco ASA ASDM exploitation method",
    "Cisco IOS Telnet credential exploitation",
    "Cisco ASA identity NAT bypass technique",
    "Cisco IOS SNMP RCE exploitation method",
    "Cisco ASA certificate validation bypass",
])

print(f"After CMS/Framework: {len(categories)} categories")

# ============ RECONNAISSANCE (50 modules) ============

add("OSINT Email Harvesting (12)", [
    "OSINT email harvesting via search engine dorking",
    "OSINT email harvesting from social media profiles",
    "OSINT email harvesting via data breach databases",
    "OSINT email pattern discovery from domain",
    "OSINT email harvesting via PGP key servers",
    "OSINT email harvesting from job postings",
    "OSINT email harvesting via WHOIS records",
    "OSINT email harvesting from PDF metadata",
    "OSINT email harvesting via Hunter.io API",
    "OSINT email harvesting from GitHub commits",
    "OSINT email validation via SMTP VRFY command",
    "OSINT email harvesting from mailing list archives",
])

add("OSINT Social Media (12)", [
    "OSINT social media profile correlation technique",
    "OSINT social media photo geolocation analysis",
    "OSINT social media connection graph mapping",
    "OSINT social media post timeline analysis",
    "OSINT social media account creation date analysis",
    "OSINT social media privacy setting enumeration",
    "OSINT social media deleted content recovery",
    "OSINT social media fake profile detection",
    "OSINT social media API data extraction method",
    "OSINT social media hashtag trend analysis",
    "OSINT social media employment verification",
    "OSINT social media location pattern analysis",
])

add("OSINT Document Metadata (12)", [
    "OSINT document metadata author extraction",
    "OSINT document metadata creation date analysis",
    "OSINT document metadata software version leak",
    "OSINT document metadata GPS coordinates extraction",
    "OSINT document metadata printer information leak",
    "OSINT document metadata network path exposure",
    "OSINT document metadata revision history analysis",
    "OSINT document metadata email address extraction",
    "OSINT document metadata username discovery",
    "OSINT document metadata hostname extraction",
    "OSINT document metadata template source identification",
    "OSINT document metadata embedded object analysis",
])

add("OSINT Code Repository (12)", [
    "OSINT code repository secret scanning technique",
    "OSINT code repository author identity correlation",
    "OSINT code repository infrastructure discovery",
    "OSINT code repository API endpoint extraction",
    "OSINT code repository dependency analysis",
    "OSINT code repository commit history analysis",
    "OSINT code repository issue tracker mining",
    "OSINT code repository CI/CD configuration exposure",
    "OSINT code repository internal URL discovery",
    "OSINT code repository technology stack profiling",
    "OSINT code repository deleted sensitive file recovery",
    "OSINT code repository fork network analysis",
])

add("OSINT Domain History (12)", [
    "OSINT domain registration history analysis",
    "OSINT domain registrant change tracking",
    "OSINT domain nameserver history correlation",
    "OSINT domain IP address history mapping",
    "OSINT domain expiration monitoring exploitation",
    "OSINT domain parking history analysis",
    "OSINT domain transfer history analysis",
    "OSINT domain age correlation for trust scoring",
    "OSINT domain similar registration discovery",
    "OSINT domain WHOIS privacy service correlation",
    "OSINT domain bulk registration detection",
    "OSINT domain drop catching opportunity detection",
])

add("OSINT Certificate Transparency (12)", [
    "OSINT CT log subdomain enumeration technique",
    "OSINT CT log certificate authority analysis",
    "OSINT CT log wildcard certificate discovery",
    "OSINT CT log internal hostname exposure",
    "OSINT CT log SAN entry analysis technique",
    "OSINT CT log certificate timeline analysis",
    "OSINT CT log pre-certificate monitoring",
    "OSINT CT log revocation pattern analysis",
    "OSINT CT log organization mapping technique",
    "OSINT CT log staging environment discovery",
    "OSINT CT log key reuse detection method",
    "OSINT CT log certificate pinning preparation",
])

add("OSINT DNS History (12)", [
    "OSINT DNS history A record change tracking",
    "OSINT DNS history MX record analysis technique",
    "OSINT DNS history NS record change correlation",
    "OSINT DNS history TXT record SPF analysis",
    "OSINT DNS history CNAME record mapping",
    "OSINT DNS history PTR record analysis",
    "OSINT DNS history SOA record timeline analysis",
    "OSINT DNS history DKIM record analysis",
    "OSINT DNS history DMARC policy tracking",
    "OSINT DNS history SRV record service discovery",
    "OSINT DNS history CAA record policy analysis",
    "OSINT DNS history zone transfer attempt detection",
])

add("OSINT Wayback Machine (12)", [
    "OSINT Wayback Machine endpoint discovery technique",
    "OSINT Wayback Machine deleted page recovery",
    "OSINT Wayback Machine technology change tracking",
    "OSINT Wayback Machine credential exposure discovery",
    "OSINT Wayback Machine admin panel history analysis",
    "OSINT Wayback Machine configuration file exposure",
    "OSINT Wayback Machine API endpoint archaeology",
    "OSINT Wayback Machine JavaScript source analysis",
    "OSINT Wayback Machine subdomain discovery method",
    "OSINT Wayback Machine form action URL discovery",
    "OSINT Wayback Machine sitemap analysis technique",
    "OSINT Wayback Machine robots.txt history analysis",
])

add("OSINT Technology Profiling (12)", [
    "OSINT technology stack identification technique",
    "OSINT CMS version fingerprinting method",
    "OSINT JavaScript framework identification",
    "OSINT server technology fingerprinting technique",
    "OSINT CDN provider identification method",
    "OSINT hosting provider identification technique",
    "OSINT email service provider identification",
    "OSINT analytics platform identification method",
    "OSINT marketing automation identification",
    "OSINT payment processor identification technique",
    "OSINT authentication provider identification",
    "OSINT third-party service enumeration method",
])

add("OSINT Employee Discovery (12)", [
    "OSINT employee LinkedIn profile enumeration",
    "OSINT employee GitHub account correlation",
    "OSINT employee email address pattern discovery",
    "OSINT employee role and title mapping technique",
    "OSINT employee technology skill profiling",
    "OSINT employee conference speaker identification",
    "OSINT employee publication author correlation",
    "OSINT employee patent holder identification",
    "OSINT employee job change monitoring technique",
    "OSINT employee social media correlation method",
    "OSINT employee former employer analysis",
    "OSINT employee clearance level inference",
])

add("Google Dorking Automation (12)", [
    "Google dork for exposed admin panels discovery",
    "Google dork for sensitive file exposure detection",
    "Google dork for database dump discovery",
    "Google dork for configuration file exposure",
    "Google dork for login page enumeration",
    "Google dork for error message information leak",
    "Google dork for backup file discovery technique",
    "Google dork for open directory listing discovery",
    "Google dork for vulnerable parameter discovery",
    "Google dork for technology-specific vulnerability",
    "Google dork for cloud storage exposure detection",
    "Google dork for API documentation discovery",
])

add("Shodan Query Integration (12)", [
    "Shodan query for exposed database services",
    "Shodan query for industrial control systems",
    "Shodan query for unpatched web servers",
    "Shodan query for default credential services",
    "Shodan query for exposed management interfaces",
    "Shodan query for vulnerable IoT devices",
    "Shodan query for SSL certificate analysis",
    "Shodan query for exposed development servers",
    "Shodan query for cloud metadata exposure",
    "Shodan query for exposed API endpoints",
    "Shodan query for organization IP enumeration",
    "Shodan query for expired certificate services",
])

add("Censys Query Integration (12)", [
    "Censys query for certificate subject analysis",
    "Censys query for organization asset enumeration",
    "Censys query for protocol support analysis",
    "Censys query for expired certificate detection",
    "Censys query for self-signed certificate discovery",
    "Censys query for subdomain enumeration technique",
    "Censys query for cloud provider asset mapping",
    "Censys query for vulnerable service identification",
    "Censys query for TLS configuration analysis",
    "Censys query for banner grab data analysis",
    "Censys query for historical host data analysis",
    "Censys query for network range enumeration",
])

add("SecurityTrails Integration (12)", [
    "SecurityTrails domain history analysis technique",
    "SecurityTrails subdomain enumeration method",
    "SecurityTrails DNS record timeline analysis",
    "SecurityTrails associated domain discovery",
    "SecurityTrails IP neighbor analysis technique",
    "SecurityTrails WHOIS data correlation method",
    "SecurityTrails company domain enumeration",
    "SecurityTrails hosting history analysis",
    "SecurityTrails NS record change detection",
    "SecurityTrails zone file analysis technique",
    "SecurityTrails API endpoint enumeration",
    "SecurityTrails bulk lookup for asset mapping",
])

add("ASN BGP Analysis (12)", [
    "ASN enumeration for organization IP mapping",
    "BGP prefix announcement monitoring technique",
    "ASN relationship mapping for supply chain",
    "BGP hijack detection and monitoring method",
    "ASN peering relationship analysis technique",
    "BGP route leak detection monitoring method",
    "ASN country allocation mapping technique",
    "BGP community string analysis exploitation",
    "ASN allocation history analysis method",
    "BGP looking glass query for route analysis",
    "ASN downstream customer enumeration technique",
    "BGP origin validation status analysis",
])

add("IP Range Discovery (12)", [
    "IP range discovery via reverse DNS enumeration",
    "IP range discovery via ASN registration data",
    "IP range discovery via certificate SAN analysis",
    "IP range discovery via DNS zone walking technique",
    "IP range discovery via PTR record scanning",
    "IP range discovery via cloud provider allocation",
    "IP range discovery via netflow data analysis",
    "IP range discovery via historical DNS data",
    "IP range discovery via WHOIS IP allocation",
    "IP range discovery via BGP prefix analysis",
    "IP range discovery via port scan correlation",
    "IP range discovery via service banner analysis",
])

add("Reverse DNS Enumeration (12)", [
    "Reverse DNS enumeration for subnet mapping",
    "Reverse DNS pattern analysis for hostname discovery",
    "Reverse DNS bulk lookup for infrastructure mapping",
    "Reverse DNS delegation analysis technique",
    "Reverse DNS zone transfer attempt exploitation",
    "Reverse DNS consistency check for anomaly detection",
    "Reverse DNS wildcard record detection method",
    "Reverse DNS timing analysis for zone size estimation",
    "Reverse DNS NSEC walking technique exploitation",
    "Reverse DNS cloud provider instance enumeration",
    "Reverse DNS mail server identification method",
    "Reverse DNS CDN origin server discovery technique",
])

add("WHOIS Analysis Techniques (12)", [
    "WHOIS registrant information correlation",
    "WHOIS registration date analysis technique",
    "WHOIS nameserver clustering analysis method",
    "WHOIS privacy service penetration technique",
    "WHOIS registrar transfer history analysis",
    "WHOIS email address correlation technique",
    "WHOIS organization name variant discovery",
    "WHOIS address information correlation method",
    "WHOIS phone number correlation technique",
    "WHOIS bulk domain ownership analysis",
    "WHOIS historical record comparison analysis",
    "WHOIS status code analysis for vulnerability",
])

add("Banner Grabbing Techniques (12)", [
    "Banner grabbing via TCP connection fingerprinting",
    "Banner grabbing via HTTP response header analysis",
    "Banner grabbing via SMTP EHLO response analysis",
    "Banner grabbing via SSH version string analysis",
    "Banner grabbing via FTP welcome message analysis",
    "Banner grabbing via DNS version.bind query",
    "Banner grabbing via SNMP sysDescr analysis",
    "Banner grabbing via TLS certificate analysis",
    "Banner grabbing via SIP OPTIONS response",
    "Banner grabbing via NTP version query technique",
    "Banner grabbing via Redis INFO command response",
    "Banner grabbing via MySQL greeting packet analysis",
])

add("Service Fingerprinting Advanced (12)", [
    "Service fingerprinting via response timing analysis",
    "Service fingerprinting via error message pattern",
    "Service fingerprinting via protocol behavior analysis",
    "Service fingerprinting via TLS cipher preference",
    "Service fingerprinting via TCP window size analysis",
    "Service fingerprinting via HTTP method support",
    "Service fingerprinting via authentication mechanism",
    "Service fingerprinting via header ordering analysis",
    "Service fingerprinting via response code behavior",
    "Service fingerprinting via content negotiation",
    "Service fingerprinting via timeout behavior analysis",
    "Service fingerprinting via connection handling pattern",
])

add("TLS Certificate Analysis (12)", [
    "TLS certificate chain validation analysis",
    "TLS certificate SAN enumeration technique",
    "TLS certificate expiration monitoring method",
    "TLS certificate key strength analysis technique",
    "TLS certificate issuer trust validation",
    "TLS certificate revocation status check",
    "TLS certificate transparency log analysis",
    "TLS certificate wildcard scope analysis",
    "TLS certificate pinning recommendation analysis",
    "TLS certificate algorithm deprecation check",
    "TLS certificate common name correlation",
    "TLS certificate organization validation level",
])

add("HTTP Fingerprinting Techniques (12)", [
    "HTTP fingerprinting via server header analysis",
    "HTTP fingerprinting via response header ordering",
    "HTTP fingerprinting via error page content",
    "HTTP fingerprinting via cookie name patterns",
    "HTTP fingerprinting via default page content",
    "HTTP fingerprinting via URL rewriting patterns",
    "HTTP fingerprinting via compression support",
    "HTTP fingerprinting via cache header behavior",
    "HTTP fingerprinting via CORS header patterns",
    "HTTP fingerprinting via CSP header analysis",
    "HTTP fingerprinting via connection handling",
    "HTTP fingerprinting via feature policy headers",
])

add("WAF Fingerprinting Advanced (12)", [
    "WAF fingerprinting via block page analysis",
    "WAF fingerprinting via response code patterns",
    "WAF fingerprinting via header injection response",
    "WAF fingerprinting via timing side channel",
    "WAF fingerprinting via payload threshold analysis",
    "WAF fingerprinting via encoding handling behavior",
    "WAF fingerprinting via cookie name patterns",
    "WAF fingerprinting via rate limit behavior",
    "WAF fingerprinting via protocol handling method",
    "WAF fingerprinting via geographic block behavior",
    "WAF fingerprinting via bot detection mechanism",
    "WAF fingerprinting via WebSocket handling behavior",
])

add("CDN Detection Advanced (12)", [
    "CDN detection via DNS CNAME analysis technique",
    "CDN detection via HTTP header analysis method",
    "CDN detection via IP range correlation technique",
    "CDN detection via certificate issuer analysis",
    "CDN detection via response timing analysis",
    "CDN detection via cache behavior analysis method",
    "CDN detection via edge server identification",
    "CDN detection via error page content analysis",
    "CDN detection via protocol support analysis",
    "CDN detection via geographic distribution test",
    "CDN detection via origin exposure technique",
    "CDN detection via purge API discovery method",
])

add("API Gateway Detection (12)", [
    "API gateway detection via response header analysis",
    "API gateway detection via rate limit behavior",
    "API gateway detection via authentication pattern",
    "API gateway detection via error response format",
    "API gateway detection via routing pattern analysis",
    "API gateway detection via throttling behavior",
    "API gateway detection via CORS implementation",
    "API gateway detection via request transformation",
    "API gateway detection via caching behavior",
    "API gateway detection via protocol support",
    "API gateway detection via versioning pattern",
    "API gateway detection via health check endpoint",
])

# ============ ADDITIONAL MODULES TO REACH 315+ ============

add("GraphQL Security Deep (12)", [
    "GraphQL introspection query information disclosure",
    "GraphQL batch query denial of service attack",
    "GraphQL nested query depth exploitation method",
    "GraphQL field suggestion information leak",
    "GraphQL alias-based rate limit bypass technique",
    "GraphQL fragment injection exploitation method",
    "GraphQL directive manipulation exploitation",
    "GraphQL subscription authorization bypass",
    "GraphQL mutation IDOR exploitation technique",
    "GraphQL query complexity bypass exploitation",
    "GraphQL persisted query manipulation method",
    "GraphQL schema stitching exploitation technique",
])

add("API Rate Limiting Bypass (12)", [
    "API rate limit bypass via IP rotation technique",
    "API rate limit bypass via header manipulation",
    "API rate limit bypass via endpoint variation",
    "API rate limit bypass via parameter padding",
    "API rate limit bypass via HTTP method switching",
    "API rate limit bypass via API version switching",
    "API rate limit bypass via authentication rotation",
    "API rate limit bypass via distributed requests",
    "API rate limit bypass via caching exploitation",
    "API rate limit bypass via batch request abuse",
    "API rate limit bypass via WebSocket downgrade",
    "API rate limit bypass via encoding variation",
])

add("Cache Poisoning Advanced (12)", [
    "Web cache poisoning via unkeyed header injection",
    "Web cache poisoning via parameter cloaking",
    "Web cache poisoning via fat GET request technique",
    "Web cache poisoning via path normalization confusion",
    "Web cache poisoning via port differential technique",
    "Web cache poisoning via cache key manipulation",
    "Web cache poisoning via vary header confusion",
    "CDN cache poisoning via origin confusion technique",
    "Web cache deception via path confusion attack",
    "Web cache poisoning via hop-by-hop headers",
    "Web cache poisoning via unknown method technique",
    "Web cache poisoning via URI parser differential",
])

add("Subdomain Takeover Advanced (12)", [
    "Subdomain takeover via dangling CNAME record",
    "Subdomain takeover via expired cloud service",
    "Subdomain takeover via deleted GitHub pages",
    "Subdomain takeover via unclaimed S3 bucket",
    "Subdomain takeover via expired Heroku application",
    "Subdomain takeover via Azure TrafficManager profile",
    "Subdomain takeover via abandoned CloudFront distribution",
    "Subdomain takeover via expired Shopify store",
    "Subdomain takeover via deleted Firebase project",
    "Subdomain takeover via unclaimed Fastly endpoint",
    "Subdomain takeover via expired Netlify site",
    "Subdomain takeover via abandoned Google Cloud instance",
])

add("Deserialization Exploitation (12)", [
    "Java deserialization via ObjectInputStream exploitation",
    "PHP deserialization via unserialize exploitation",
    "Python pickle deserialization RCE exploitation",
    ".NET deserialization via BinaryFormatter exploitation",
    "Ruby deserialization via Marshal.load exploitation",
    "Node.js deserialization via node-serialize exploitation",
    "Java deserialization via Fastjson exploitation method",
    "PHP deserialization via phar wrapper exploitation",
    "Python YAML deserialization exploitation technique",
    ".NET deserialization via ViewState exploitation",
    "Java deserialization via Log4j JNDI exploitation",
    "Java deserialization via SnakeYAML exploitation",
])

add("Template Injection Advanced (12)", [
    "Jinja2 SSTI exploitation for RCE technique",
    "Twig SSTI exploitation for file read method",
    "Freemarker SSTI exploitation for code execution",
    "Thymeleaf SSTI exploitation technique method",
    "Pebble SSTI exploitation for Java RCE",
    "Velocity SSTI exploitation for command execution",
    "Mako SSTI exploitation for Python RCE",
    "Smarty SSTI exploitation for PHP code execution",
    "ERB SSTI exploitation for Ruby RCE technique",
    "Handlebars SSTI exploitation for prototype access",
    "Tornado SSTI exploitation for Python command exec",
    "Dust.js SSTI exploitation for server-side access",
])

add("Command Injection Advanced (12)", [
    "OS command injection via shell metacharacters",
    "Command injection via backtick substitution",
    "Command injection via pipe operator exploitation",
    "Command injection via semicolon separator abuse",
    "Command injection via newline character injection",
    "Command injection via environment variable expansion",
    "Command injection via glob pattern exploitation",
    "Command injection via argument injection technique",
    "Command injection via file name manipulation",
    "Command injection via locale variable exploitation",
    "Command injection via time-based blind technique",
    "Command injection via DNS-based exfiltration",
])

add("Authentication Bypass Advanced (12)", [
    "Authentication bypass via type juggling exploitation",
    "Authentication bypass via null byte injection",
    "Authentication bypass via response manipulation",
    "Authentication bypass via timing side channel",
    "Authentication bypass via password reset flow",
    "Authentication bypass via remember me token forge",
    "Authentication bypass via SSO assertion manipulation",
    "Authentication bypass via 2FA race condition",
    "Authentication bypass via backup code brute force",
    "Authentication bypass via account recovery abuse",
    "Authentication bypass via magic link prediction",
    "Authentication bypass via social login confusion",
])

add("Business Logic Exploitation Deep (12)", [
    "Business logic coupon stacking exploitation",
    "Business logic negative quantity manipulation",
    "Business logic race condition in inventory",
    "Business logic currency rounding exploitation",
    "Business logic trial period extension technique",
    "Business logic referral system manipulation",
    "Business logic loyalty point exploitation method",
    "Business logic subscription downgrade data retention",
    "Business logic gift card generation prediction",
    "Business logic free shipping threshold manipulation",
    "Business logic cancellation refund exploitation",
    "Business logic auction sniping exploitation method",
])

add("CORS Exploitation Deep (12)", [
    "CORS exploitation via null origin acceptance",
    "CORS exploitation via subdomain wildcard trust",
    "CORS exploitation via regex origin bypass",
    "CORS exploitation via pre-domain wildcard trust",
    "CORS exploitation via post-domain wildcard trust",
    "CORS exploitation via special characters in origin",
    "CORS exploitation via browser bug exploitation",
    "CORS exploitation via DNS rebinding combination",
    "CORS exploitation via cache poisoning chain",
    "CORS exploitation via WebSocket origin bypass",
    "CORS exploitation via CDN same-origin confusion",
    "CORS exploitation via origin reflection vulnerability",
])

add("Supply Chain Security (12)", [
    "Supply chain attack via compromised npm package",
    "Supply chain attack via typosquatting package name",
    "Supply chain attack via GitHub Action compromise",
    "Supply chain attack via Docker image manipulation",
    "Supply chain attack via CI/CD pipeline injection",
    "Supply chain attack via compromised CDN resource",
    "Supply chain attack via package maintainer takeover",
    "Supply chain attack via build tool manipulation",
    "Supply chain attack via compiler backdoor technique",
    "Supply chain attack via code signing key compromise",
    "Supply chain attack via package registry confusion",
    "Supply chain attack via upstream dependency compromise",
])

add("Cryptographic Weakness Detection (12)", [
    "Weak TLS cipher suite detection technique",
    "Insecure random number generation detection",
    "Deprecated hash algorithm usage identification",
    "Insufficient key length detection method",
    "Missing certificate validation detection",
    "Insecure key storage identification technique",
    "Padding oracle vulnerability detection method",
    "CBC mode IV reuse vulnerability detection",
    "ECB mode usage detection for sensitive data",
    "Weak password hashing algorithm detection",
    "Missing HSTS header detection technique",
    "Certificate pinning absence detection method",
])

add("Information Disclosure Deep (12)", [
    "Source code exposure via backup file discovery",
    "Git repository exposure via .git directory access",
    "Environment variable exposure via error pages",
    "Internal IP address disclosure detection",
    "Software version disclosure via headers analysis",
    "Database schema exposure via error messages",
    "API documentation exposure via common paths",
    "Cloud credentials exposure in source code",
    "JWT secret exposure via public repository",
    "Private key exposure via misconfigured server",
    "Session token exposure in URL parameters",
    "Internal architecture exposure via debug endpoints",
])

add("Race Condition Exploitation (12)", [
    "Race condition in account balance operations",
    "Race condition in coupon redemption flow",
    "Race condition in file upload processing",
    "Race condition in vote/like operations",
    "Race condition in user registration flow",
    "Race condition in limit-once actions exploitation",
    "Race condition in database transaction isolation",
    "Race condition in session creation process",
    "Race condition in token refresh mechanism",
    "Race condition in payment processing flow",
    "Race condition in permission check evaluation",
    "Race condition in inventory management system",
])

add("SSRF to RCE Chains (12)", [
    "SSRF to RCE via cloud metadata credential pivot",
    "SSRF to RCE via internal Jenkins exploitation",
    "SSRF to RCE via internal Redis command injection",
    "SSRF to RCE via internal Docker API exploitation",
    "SSRF to RCE via internal Kubernetes API access",
    "SSRF to RCE via internal Elasticsearch exploitation",
    "SSRF to RCE via internal Consul API exploitation",
    "SSRF to RCE via internal Solr exploitation chain",
    "SSRF to RCE via internal Apache Spark exploitation",
    "SSRF to RCE via internal Jupyter notebook access",
    "SSRF to RCE via internal Airflow API exploitation",
    "SSRF to RCE via internal Grafana exploitation chain",
])

add("WAF Bypass Techniques (12)", [
    "WAF bypass via Unicode normalization technique",
    "WAF bypass via HTTP parameter pollution method",
    "WAF bypass via chunked transfer encoding",
    "WAF bypass via content type confusion technique",
    "WAF bypass via double URL encoding method",
    "WAF bypass via null byte injection technique",
    "WAF bypass via multipart boundary manipulation",
    "WAF bypass via HTTP/2 header manipulation",
    "WAF bypass via large request body technique",
    "WAF bypass via request method confusion attack",
    "WAF bypass via IP reputation evasion method",
    "WAF bypass via payload fragmentation technique",
])

add("Cloud Metadata Exploitation (12)", [
    "AWS metadata v1 SSRF credential extraction",
    "GCP metadata server token theft technique",
    "Azure IMDS token extraction exploitation method",
    "DigitalOcean metadata exploitation technique",
    "Oracle Cloud metadata access exploitation",
    "Alibaba Cloud metadata exploitation method",
    "Cloud metadata user-data secret extraction",
    "Cloud metadata network configuration exposure",
    "Cloud metadata instance identity theft",
    "Cloud metadata SSH key extraction technique",
    "Cloud metadata hostname enumeration method",
    "Cloud metadata IAM role discovery technique",
])

add("Container Security Advanced (12)", [
    "Container image secret scanning technique",
    "Container runtime privilege escalation method",
    "Container network policy bypass exploitation",
    "Container volume mount exploitation technique",
    "Container resource limit bypass exploitation",
    "Container capabilities exploitation method",
    "Container seccomp profile bypass technique",
    "Container SELinux label manipulation attack",
    "Container cgroup escape exploitation method",
    "Container PID namespace exploitation technique",
    "Container IPC namespace exploitation method",
    "Container UTS namespace manipulation attack",
])

add("API Security Testing Deep (12)", [
    "API broken object-level authorization testing",
    "API broken authentication mechanism detection",
    "API excessive data exposure identification",
    "API lack of resources and rate limiting test",
    "API broken function-level authorization check",
    "API mass assignment vulnerability detection",
    "API security misconfiguration identification",
    "API injection vulnerability detection technique",
    "API improper asset management detection",
    "API insufficient logging monitoring detection",
    "API server-side request forgery testing",
    "API unsafe consumption of external APIs",
])

add("Zero Day Pattern Detection (12)", [
    "Zero-day pattern via memory corruption indication",
    "Zero-day pattern via integer overflow detection",
    "Zero-day pattern via use-after-free indication",
    "Zero-day pattern via buffer overflow detection",
    "Zero-day pattern via format string vulnerability",
    "Zero-day pattern via type confusion indication",
    "Zero-day pattern via race condition detection",
    "Zero-day pattern via logic error indication",
    "Zero-day pattern via path traversal variant",
    "Zero-day pattern via auth bypass variant detection",
    "Zero-day pattern via injection variant detection",
    "Zero-day pattern via deserialization variant",
])

print(f"TOTAL categories: {len(categories)}")

# ============ WRITE THE ROADMAP FILE ============

with open(OUTPUT, 'w') as f:
    f.write("# Apex-CLI Extended Roadmap — 500 Target Expansion\n\n")
    check_num = 1
    for cat_name, checks in categories:
        f.write(f"## {cat_name}\n")
        for check in checks:
            f.write(f"{check_num}. {check}\n")
            check_num += 1
        f.write("\n")

print(f"Written {check_num - 1} checks across {len(categories)} categories to {OUTPUT}")
