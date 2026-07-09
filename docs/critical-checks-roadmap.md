# Apex-CLI Extended Roadmap — 407 New Checks

## Azure AD / Microsoft 365 (20)
1. Azure AD user enumeration via GetCredentialType
2. Azure AD tenant discovery via OpenID configuration
3. Microsoft 365 autodiscover exposure
4. Azure AD password spray detection (no lockout)
5. Azure AD conditional access bypass
6. Microsoft Teams webhook abuse
7. SharePoint anonymous access
8. OneDrive public link enumeration
9. Azure AD B2C misconfiguration
10. Microsoft Graph API anonymous access
11. Azure AD app registration secrets in source
12. Microsoft 365 mail forwarding rules (BEC indicator)
13. Azure AD guest user enumeration
14. Microsoft ADFS endpoint exposure
15. Azure AD PRT token detection
16. Microsoft 365 admin portal access
17. Azure AD device code phishing endpoint
18. Microsoft Power Automate flow exposure
19. Azure AD SAML misconfiguration
20. Microsoft Entra ID token endpoint abuse

## SSO & Identity Provider (20)
21. SAML signature wrapping attack
22. SAML assertion replay
23. SAML recipient mismatch
24. SAML audience restriction bypass
25. SSO open redirect via relay parameter
26. SSO session fixation
27. Okta user enumeration
28. Auth0 tenant misconfiguration
29. Auth0 universal login customization XSS
30. Keycloak admin console exposure
31. Keycloak realm info disclosure
32. CAS protocol redirect bypass
33. LDAP authentication bypass
34. Kerberos ticket enumeration
35. SAML metadata exposure
36. SSO callback URL manipulation
37. Identity provider confusion attack
38. Multi-tenant SSO isolation bypass
39. SSO token replay across services
40. SAML XML comment injection

## Payment & Financial (25)
41. Stripe API key exposure in JavaScript
42. Payment amount manipulation via API
43. Currency conversion exploitation
44. Payment intent manipulation
45. Subscription tier bypass
46. Free trial infinite extension
47. Coupon code generation pattern
48. Refund amount manipulation
49. Payment webhook signature bypass
50. Double-charge via race condition
51. Payment status polling manipulation
52. Invoice IDOR
53. Billing address swap after payment
54. Gift card balance enumeration
55. Cryptocurrency wallet address swap
56. Payment gateway downgrade attack
57. PCI DSS cardholder data exposure
58. Payment confirmation page data leak
59. Recurring payment cancellation bypass
60. Payment method enumeration
61. Discount stacking beyond intended limit
62. Tax calculation manipulation
63. Shipping cost negative value
64. Wallet top-up race condition
65. Payment split manipulation

## Email Security (15)
66. SPF record misconfiguration
67. DMARC policy none/quarantine (not reject)
68. DKIM selector enumeration
69. Email header injection via contact form
70. SMTP open relay detection
71. Email template injection
72. Mailgun/SendGrid API key in source
73. Email bounce enumeration
74. Mailing list subscription without confirmation
75. Email tracking pixel injection
76. MTA-STS policy missing
77. BIMI record validation
78. Email spoofing via subdomain
79. Catch-all email configuration detection
80. Email gateway version disclosure

## DNS & Domain (20)
81. DNS zone transfer (AXFR)
82. DNS cache poisoning indicators
83. Dangling CNAME records
84. Dangling NS records
85. Dangling MX records
86. DNS rebinding susceptibility
87. Wildcard DNS detection
88. DNS TXT record secrets
89. CAA record missing
90. DNSSEC not enabled
91. Subdomain brute-force via wordlist
92. DNS history changes (SecurityTrails pattern)
93. PTR record information leak
94. SRV record exposure (internal services)
95. DNS amplification risk
96. Domain fronting detection
97. Expired domain takeover indicators
98. Nameserver version disclosure
99. DNS tunneling indicators
100. Multi-CDN configuration detection

## API Authentication (20)
101. API key in URL query parameter
102. API key rotation not enforced
103. API key scope too broad
104. Bearer token in URL
105. OAuth2 client credentials in source
106. API key valid after user deletion
107. API key shared across environments
108. API rate limit bypass via key rotation
109. API authentication downgrade
110. API key brute-force (short key space)
111. GraphQL authentication bypass via aliases
112. API key in error messages
113. API key in browser localStorage
114. API key in mobile app binary
115. API key in git commit history
116. API HMAC signature bypass
117. API timestamp replay window too large
118. API nonce reuse detection
119. API mutual TLS missing
120. API key in Referer header leak

## Session Management (20)
121. Session token in URL
122. Session not invalidated on logout
123. Session not invalidated on password change
124. Session fixation via cookie injection
125. Session token low entropy
126. Session timeout too long
127. Concurrent session limit missing
128. Session token predictable pattern
129. Session cookie missing Secure flag
130. Session cookie missing HttpOnly flag
131. Session cookie missing SameSite
132. Session cookie domain too broad
133. Session token in response body
134. Session rotation missing after privilege change
135. Remember-me token persistent forever
136. Session binding to IP missing
137. Session token in WebSocket URL
138. Cross-subdomain session leakage
139. Session token length insufficient
140. Session revival after timeout

## Input Validation (25)
141. Unicode normalization bypass
142. Null byte injection in file paths
143. Double encoding bypass
144. Parameter pollution (HPP)
145. JSON injection in string fields
146. XML comment injection
147. YAML deserialization
148. CSV formula injection in exports
149. PDF injection via user input
150. SVG injection via file upload
151. Markdown injection (XSS via markdown)
152. Template literal injection
153. Regular expression DoS (ReDoS)
154. Integer overflow in calculations
155. Float precision manipulation
156. Array index out of bounds
157. Type juggling (PHP-style)
158. Mass assignment via JSON merge
159. GraphQL nested query DoS
160. Prototype pollution via query string
161. HTTP parameter name injection
162. Backslash interpretation differences
163. Homoglyph attack in usernames
164. Zero-width character injection
165. Control character injection in headers

## File Operations (20)
166. Arbitrary file read via path traversal
167. Arbitrary file write via upload
168. File extension double handling
169. MIME type mismatch exploitation
170. Polyglot file upload (valid image + code)
171. ZIP bomb upload
172. ZIP slip (path traversal in archives)
173. TAR symlink extraction
174. Image metadata EXIF data leak
175. SVG SSRF via xlink:href
176. PDF SSRF via annotations
177. DOCX XXE via embedded XML
178. XLSX formula injection
179. File upload size limit bypass
180. File upload content-type bypass
181. File upload double extension bypass
182. File overwrite via duplicate name
183. Temporary file exposure
184. Upload directory listing
185. File download IDOR

## WebSocket (15)
186. WebSocket authentication missing
187. WebSocket origin validation bypass
188. WebSocket message injection
189. WebSocket cross-site hijacking
190. WebSocket sensitive data exposure
191. WebSocket rate limiting missing
192. WebSocket reconnection token leak
193. WebSocket binary message parsing
194. WebSocket subscription to other users
195. WebSocket command injection
196. WebSocket IDOR via channel name
197. WebSocket DoS via large messages
198. WebSocket ping/pong abuse
199. WebSocket protocol downgrade
200. WebSocket event replay

## GraphQL Extended (15)
201. GraphQL introspection in production
202. GraphQL field suggestion enumeration
203. GraphQL alias-based DoS
204. GraphQL batched query brute-force
205. GraphQL circular fragment DoS
206. GraphQL unauthorized mutation access
207. GraphQL IDOR via node ID
208. GraphQL subscription data leakage
209. GraphQL type confusion
210. GraphQL directive overloading
211. GraphQL persisted query bypass
212. GraphQL custom scalar injection
213. GraphQL file upload abuse
214. GraphQL error message information leak
215. GraphQL query cost analysis bypass

## Cloud Storage (20)
216. AWS S3 bucket write access
217. AWS S3 bucket policy misconfiguration
218. AWS S3 object ACL public-read
219. GCS bucket public write
220. Azure Blob anonymous access
221. Azure Blob container listing
222. DigitalOcean Spaces public access
223. Backblaze B2 bucket exposure
224. Wasabi bucket misconfiguration
225. MinIO public access
226. Cloud storage CORS misconfiguration
227. Cloud storage signed URL expiry too long
228. Cloud storage presigned URL generation flaw
229. Cloud storage bucket name enumeration
230. Cloud storage metadata exposure
231. Cloud storage versioning data leak
232. Cloud storage lifecycle policy abuse
233. Cloud storage cross-account access
234. Cloud storage encryption missing
235. Cloud storage access logging disabled

## Container & Orchestration (15)
236. Docker socket HTTP API exposed
237. Docker registry without auth
238. Kubernetes dashboard exposed
239. Kubernetes API anonymous access
240. Kubernetes secrets in environment
241. Kubernetes service account token leak
242. Helm chart values exposure
243. Docker Compose secrets in file
244. Container running as root
245. Container with host network
246. Container with privileged mode
247. Kubernetes RBAC misconfiguration
248. Container image vulnerability (known CVE)
249. Kubernetes ingress misconfiguration
250. etcd exposed without auth

## CI/CD Security (15)
251. GitHub Actions secrets in logs
252. GitHub Actions GITHUB_TOKEN scope
253. GitLab CI variable exposure
254. Jenkins script console access
255. Jenkins credential extraction
256. CircleCI environment variable leak
257. Travis CI secrets in build log
258. GitHub Actions workflow injection
259. GitLab Runner token exposure
260. Bitbucket pipeline secrets
261. Azure DevOps PAT token leak
262. Code signing key exposure
263. Build artifact credential leak
264. Deployment script secrets
265. GitHub Actions step output injection

## Serverless & Edge (15)
266. AWS Lambda function URL without auth
267. AWS Lambda environment variable secrets
268. AWS API Gateway misconfiguration
269. Cloudflare Worker secrets in source
270. Vercel serverless function exposure
271. Netlify function information leak
272. Azure Functions anonymous access
273. GCP Cloud Functions public access
274. AWS Step Functions state leak
275. Lambda layer secrets exposure
276. API Gateway WAF bypass
277. Serverless cold start timing attack
278. Edge function cache confusion
279. Serverless function timeout abuse
280. AWS EventBridge rule manipulation

## Mobile App Security (20)
281. Android manifest exported activities
282. Android deep link hijacking
283. iOS universal link misconfiguration
284. Mobile app certificate pinning bypass indicators
285. Mobile API endpoint hardcoded in app
286. Mobile app insecure data storage
287. Mobile app debug mode enabled
288. Mobile app backup flag enabled
289. Mobile app clipboard data leakage
290. Mobile app screenshot prevention missing
291. Mobile app root/jailbreak detection bypass
292. Mobile push notification token leak
293. Mobile app WebView JavaScript bridge
294. Mobile app intent redirection
295. Mobile app binary secret extraction
296. Mobile app transport security exception
297. Mobile app biometric bypass
298. Mobile app local authentication bypass
299. Mobile app keychain/keystore weakness
300. Mobile app obfuscation missing

## Rate Limiting & DoS (15)
301. Login rate limit missing
302. Registration rate limit missing
303. Password reset rate limit missing
304. API endpoint rate limit missing
305. GraphQL query complexity unlimited
306. File upload size unlimited
307. Search query amplification
308. Regex-based DoS (ReDoS)
309. XML bomb (billion laughs)
310. JSON nesting depth unlimited
311. Pagination parameter abuse
312. Bulk operation no limit
313. Notification flood
314. WebSocket connection flood
315. Server-Sent Events stream flood

## Information Disclosure Extended (25)
316. Stack trace in production response
317. Debug mode enabled (Django/Laravel/Flask)
318. Database error message exposure
319. Internal IP in response headers
320. Server version in headers
321. Framework version exposure
322. API documentation publicly accessible
323. Source map files accessible
324. Git repository exposed (.git/HEAD)
325. SVN repository exposed (.svn/entries)
326. Environment file exposed (.env)
327. Configuration backup file exposed
328. Database dump file exposed
329. Log file publicly accessible
330. Temporary file exposure
331. IDE project files exposed (.idea, .vscode)
332. Package manager files exposed (package.json with private deps)
333. Composer.lock with vulnerable packages
334. Error page path disclosure
335. CORS error leaks internal URL
336. Timing-based user enumeration
337. HTTP TRACE method enabled
338. PROPFIND/WebDAV method enabled
339. OPTIONS method excessive disclosure
340. ETag tracking identifier

## Cryptography (15)
341. Weak TLS version (TLS 1.0/1.1)
342. Weak cipher suites
343. Self-signed certificate
344. Certificate expiry within 30 days
345. Certificate CN mismatch
346. Missing certificate transparency
347. Weak key size (RSA < 2048)
348. MD5/SHA1 signature algorithm
349. HSTS missing or too short max-age
350. HPKP deprecated but present
351. Mixed content (HTTP resources on HTTPS)
352. Cookie without Secure flag on HTTPS
353. Weak random number generation
354. Hardcoded encryption key
355. IV reuse in encryption

## Business Logic Extended (25)
356. Account deletion without confirmation
357. Email change without verification
358. Phone change without verification
359. Password change without current password
360. Profile update race condition
361. Invitation link reuse after acceptance
362. Invitation link enumeration
363. Account merge confusion
364. Multi-step form manipulation
365. Workflow state machine bypass
366. Time-of-check-time-of-use (TOCTOU)
367. Negative quantity exploitation
368. Zero-price item exploitation
369. Bulk discount threshold manipulation
370. Referral self-referral detection
371. Vote/like duplicate detection bypass
372. Content approval workflow skip
373. Draft content public access
374. Scheduled content premature access
375. Feature flag manipulation
376. A/B test forced variant
377. Geolocation restriction bypass
378. Age verification bypass
379. Terms acceptance bypass
380. Mandatory field client-side only

## Privacy & Compliance (15)
381. Cookie consent bypass
382. Analytics tracking without consent
383. PII in URL parameters
384. PII in error messages
385. PII in API responses (over-fetching)
386. Right to deletion incomplete
387. Data export contains other users
388. Account data visible to support staff
389. Audit log tampering
390. GDPR subject access request bypass
391. Data retention policy violation
392. Cross-border data transfer indicators
393. Marketing preference bypass
394. Unsubscribe link missing
395. Do-Not-Track header ignored

## Third-Party Integration (12)
396. Third-party script integrity missing (no SRI)
397. Third-party script loading from HTTP
398. Analytics provider data leakage
399. Social login token exposure
400. Payment SDK outdated version
401. Chat widget XSS via visitor input
402. CDN cache poisoning via host header
403. Third-party API key exposure
404. Third-party webhook secret missing
405. OAuth third-party scope creep
406. Embedded iframe sandbox missing
407. Third-party library known CVE
# Apex-CLI Extended Roadmap Part 2 — 200 More Checks

## WordPress Deep (20)
1. WordPress REST API user listing without auth
2. WordPress xmlrpc.php pingback SSRF
3. WordPress xmlrpc.php brute-force amplification
4. WordPress debug.log exposure
5. WordPress wp-config.php backup exposure
6. WordPress plugin directory listing
7. WordPress theme file inclusion
8. WordPress upload directory PHP execution
9. WordPress cron jobs manipulation
10. WordPress user registration enabled
11. WordPress default admin credentials
12. WordPress database repair page exposure
13. WordPress install.php accessible
14. WordPress readme.html version leak
15. WordPress license.txt exposure
16. WordPress REST API post content without auth
17. WordPress REST API media enumeration
18. WordPress oEmbed SSRF
19. WordPress Gutenberg block injection
20. WordPress multisite subdomain takeover

## Next.js / React Deep (15)
21. Next.js server action CSRF
22. Next.js middleware bypass via path encoding
23. Next.js RSC data leakage in response
24. Next.js build manifest exposure
25. Next.js source map exposure
26. Next.js API route handler bypass
27. React dangerouslySetInnerHTML XSS sink
28. React state serialization injection
29. React hydration mismatch exploitation
30. Next.js image optimization SSRF
31. Next.js revalidation path poisoning
32. React router path traversal
33. Next.js draft mode token leak
34. Next.js preview mode bypass
35. React useEffect side-channel

## Laravel / PHP Deep (15)
36. Laravel APP_KEY exposure
37. Laravel debug mode stack trace
38. Laravel Ignition RCE (CVE-2021-3129)
39. Laravel mass assignment via fillable
40. Laravel password reset token prediction
41. Laravel session fixation
42. PHP object injection via unserialize
43. PHP type juggling in comparison
44. PHP file inclusion via wrapper
45. Laravel Telescope exposure
46. Laravel Horizon dashboard access
47. PHP opcache status exposure
48. Laravel log viewer access
49. PHP xdebug remote enabled
50. Laravel Nova admin access

## Django / Python Deep (15)
51. Django DEBUG=True information disclosure
52. Django admin panel exposure
53. Django SECRET_KEY in error page
54. Django ALLOWED_HOSTS bypass
55. Django template injection
56. Django CSRF token prediction
57. Python pickle deserialization
58. Flask debug mode RCE (Werkzeug console)
59. Django REST framework browsable API exposure
60. FastAPI documentation exposure
61. Python subprocess injection
62. Jinja2 SSTI via user input
63. Django ORM injection
64. Flask session cookie decode
65. Django collectstatic sensitive files

## Spring / Java Deep (15)
66. Spring Boot Actuator env endpoint
67. Spring Boot Actuator heapdump
68. Spring Boot Actuator logfile
69. Spring Boot Actuator shutdown
70. Spring SpEL injection
71. Java deserialization via gadget chains
72. Tomcat manager default credentials
73. Tomcat AJP Ghostcat (CVE-2020-1938)
74. Spring Cloud Gateway SSRF
75. Spring Data REST IDOR
76. Java JNDI injection (Log4Shell pattern)
77. Spring Security CORS bypass
78. Struts2 OGNL injection
79. Spring MVC path traversal
80. JBoss/WildFly deployment scanning

## Node.js / Express Deep (15)
81. Express.js SSRF via request module
82. Node.js eval injection
83. Express.js session secret weak
84. Node.js child_process injection
85. Express.js CORS wildcard with credentials
86. npm package.json scripts injection
87. Node.js Buffer allocation uninitialized
88. Express.js HPP (HTTP Parameter Pollution)
89. Node.js path traversal via path.join
90. Express.js body-parser limit bypass
91. Node.js crypto weak randomness
92. Express.js template engine injection
93. Node.js event loop blocking DoS
94. Express.js trust proxy misconfiguration
95. Node.js require hijacking

## OAuth 2.0 / OIDC Deep (15)
96. OAuth authorization code interception
97. OAuth PKCE downgrade attack
98. OAuth scope escalation via modified request
99. OAuth token leakage via browser history
100. OAuth refresh token rotation missing
101. OAuth client secret in frontend code
102. OIDC ID token audience confusion
103. OIDC nonce replay attack
104. OAuth device code flow abuse
105. OAuth dynamic client registration abuse
106. OAuth pushed authorization request bypass
107. OAuth token exchange abuse
108. OAuth resource indicator manipulation
109. OIDC logout redirect manipulation
110. OAuth consent screen bypass

## Cache & CDN Deep (15)
111. CDN cache key manipulation
112. CDN cache poisoning via X-Forwarded-Host
113. Browser cache poisoning via Service Worker
114. HTTP response splitting via CRLF
115. Cache deception via path parameter
116. Cache deception via semicolon separator
117. Vary header cache confusion
118. Edge Side Include injection (ESI)
119. CDN bypass via origin IP
120. Cache key normalization difference
121. Fragment caching exposure
122. Reverse proxy cache poisoning
123. CDN origin validation bypass
124. Client-side cache sensitive data
125. Cache timing side-channel

## HTTP Protocol (15)
126. HTTP/2 CONTINUATION frame flood
127. HTTP/2 SETTINGS frame abuse
128. HTTP/2 stream multiplexing abuse
129. HTTP request smuggling TE.TE
130. HTTP request smuggling CL.0
131. HTTP response queue poisoning
132. HTTP method override via header
133. HTTP verb tampering
134. HTTP header injection via CRLF
135. HTTP trailer injection
136. HTTP 100 Continue abuse
137. HTTP Range header DoS
138. HTTP multipart boundary confusion
139. HTTP Content-Type confusion
140. HTTP chunked encoding abuse

## Subdomain & DNS Extended (15)
141. Subdomain takeover via expired Heroku
142. Subdomain takeover via unclaimed S3
143. Subdomain takeover via GitHub Pages
144. Subdomain takeover via Azure
145. Subdomain takeover via Fastly
146. Subdomain takeover via Shopify
147. Subdomain takeover via Netlify
148. Subdomain takeover via Vercel
149. Subdomain takeover via Fly.io
150. Subdomain bruteforce via permutation
151. Virtual host discovery
152. DNS pinning bypass
153. DNS over HTTPS configuration leak
154. Internal subdomain via certificate transparency
155. Subdomain via response header analysis

## Encoding & Parser Differential (15)
156. URL parser differential exploitation
157. Unicode case mapping bypass
158. Punycode/IDN homograph attack
159. Double URL decoding bypass
160. Backslash vs forward slash confusion
161. Null byte injection in parsers
162. UTF-8 overlong encoding bypass
163. URL fragment handling difference
164. JSON vs form-data parsing difference
165. XML namespace confusion
166. HTML entity encoding bypass
167. Base64 padding manipulation
168. Hex encoding bypass in WAF
169. URL parameter delimiter confusion (&/;)
170. Path normalization difference (../ handling)

## Monitoring & Observability (10)
171. Prometheus metrics endpoint exposure
172. Grafana anonymous access
173. Jaeger tracing UI exposure
174. Sentry DSN public key abuse
175. ELK stack Kibana exposure
176. Datadog API key in source
177. New Relic license key exposure
178. PagerDuty integration key leak
179. Slack webhook URL exposure
180. Discord webhook URL exposure

## AI/LLM Security (20)
181. LLM prompt injection via user input
182. LLM system prompt extraction
183. LLM jailbreak via roleplay
184. LLM API key in frontend
185. RAG document poisoning indicators
186. LLM output injection (XSS via AI response)
187. AI model endpoint without auth
188. Vector database public access
189. AI training data exposure
190. LLM token limit exploitation
191. AI agent tool abuse
192. AI function calling manipulation
193. MCP server tool poisoning
194. MCP server authentication bypass
195. AI embedding endpoint enumeration
196. LLM conversation history exposure
197. AI model version disclosure
198. AI safety filter bypass
199. LLM data exfiltration via prompt
200. AI plugin/extension vulnerability
