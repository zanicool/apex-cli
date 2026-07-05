# Apex CLI — 200+ Critical Vulnerability Checks To Add

## Authentication & Account Takeover (25)
1. Password reset token in URL (predictable/leaked via Referer)
2. Password reset token reuse (use same token twice)
3. Password reset for any email (no ownership verification)
4. OAuth state parameter missing/predictable
5. OAuth redirect_uri manipulation (open redirect → token theft)
6. OAuth scope escalation (request more permissions)
7. JWT none algorithm bypass
8. JWT weak secret (brute-force HS256 key)
9. JWT algorithm confusion (RS256 → HS256)
10. JWT kid header injection (path traversal/SQLi)
11. 2FA bypass via direct navigation to dashboard
12. 2FA bypass via null/empty code
13. 2FA bypass via response manipulation (change "success":false → true)
14. 2FA code brute-force (no rate limit on verification)
15. 2FA backup codes exposed in API response
16. Session fixation (pre-login session persists post-login)
17. Session not invalidated after password change
18. Session not invalidated after email change
19. Concurrent session abuse (no session limit)
20. Login CSRF (force victim to login as attacker)
21. Account takeover via HTTP parameter pollution
22. Account takeover via case sensitivity (User@email vs user@email)
23. Account takeover via unicode normalization
24. Magic link token prediction
25. SSO/SAML response manipulation

## IDOR & Broken Access Control (30)
26. Numeric ID enumeration on user endpoints
27. UUID/GUID prediction on resources
28. Base64 decoded IDs revealing sequential numbers
29. GraphQL node() query with other user's ID
30. Horizontal privilege escalation (user A → user B data)
31. Vertical privilege escalation (user → admin)
32. API endpoint accessible without auth header
33. Admin panel accessible to regular users
34. Modify other user's profile via PUT/PATCH
35. Delete other user's resources
36. Access other user's orders/transactions
37. Access other user's messages/DMs
38. Access other user's payment methods
39. Access other user's address/PII
40. Modify other user's listing/product
41. Cancel other user's order
42. View other user's analytics/stats
43. Download other user's invoices/receipts
44. Access other user's notifications
45. Modify other user's settings
46. Force-follow/unfollow other users
47. Access internal/admin API endpoints
48. Bypass IP-based access control
49. Bypass geo-restriction
50. Access deprecated API versions with weaker auth
51. Tenant isolation bypass (multi-tenant apps)
52. Object-level authorization bypass via nested resources
53. Function-level authorization bypass
54. Broken access control via HTTP method override (X-HTTP-Method-Override)
55. Access control bypass via URL encoding/double encoding

## Injection (30)
56. SQL injection (error-based)
57. SQL injection (time-based blind)
58. SQL injection (boolean-based blind)
59. SQL injection (UNION-based)
60. SQL injection in ORDER BY clause
61. SQL injection in JSON body
62. SQL injection in HTTP headers (User-Agent, Referer, X-Forwarded-For)
63. NoSQL injection (MongoDB $gt, $ne operators)
64. NoSQL injection in JSON body
65. OS command injection (;, |, &&, ||, backticks)
66. OS command injection (time-based blind)
67. Server-Side Template Injection (Jinja2, Twig, Freemarker)
68. SSTI in email templates
69. SSTI in PDF generation
70. Expression Language injection (Spring EL, OGNL)
71. LDAP injection
72. XPath injection
73. XML External Entity (XXE) injection
74. XXE via file upload (SVG, DOCX, XLSX)
75. XXE via SOAP endpoints
76. CRLF injection in HTTP headers
77. CRLF injection → HTTP response splitting
78. Log injection (forge log entries)
79. CSV injection (formula injection in exports)
80. LaTeX injection (in PDF generators)
81. GraphQL injection (nested queries, aliases for DoS)
82. GraphQL batch query abuse
83. GraphQL directive overloading
84. Server-Side JavaScript injection (Node.js eval)
85. Prototype pollution (server-side)

## SSRF (20)
86. SSRF via URL parameter
87. SSRF via webhook URL
88. SSRF via PDF generator (HTML → PDF)
89. SSRF via image URL (avatar, thumbnail)
90. SSRF via import/export functionality
91. SSRF via SVG file upload
92. SSRF via DNS rebinding
93. SSRF via redirect chain (302 → internal)
94. SSRF to AWS metadata (169.254.169.254)
95. SSRF to GCP metadata
96. SSRF to Azure metadata
97. SSRF to internal services (localhost, 127.0.0.1)
98. SSRF to internal network (10.x, 172.16.x, 192.168.x)
99. SSRF via URL parser differential (Java vs Python)
100. SSRF via IPv6 (::1, ::ffff:127.0.0.1)
101. SSRF via decimal IP (2130706433)
102. SSRF via octal IP (0177.0.0.1)
103. SSRF via URL shortener bypass
104. SSRF via open redirect chain
105. Blind SSRF via OOB (DNS/HTTP callback)

## XSS (20)
106. Reflected XSS in search/query params
107. Stored XSS in profile fields (name, bio)
108. Stored XSS in messages/comments
109. Stored XSS in file names
110. DOM XSS via URL fragment (#)
111. DOM XSS via postMessage
112. DOM XSS via document.location
113. DOM XSS via innerHTML/outerHTML
114. XSS via SVG upload
115. XSS via PDF metadata
116. XSS in error messages
117. XSS in email templates (HTML injection)
118. XSS via Content-Type sniffing
119. XSS via JSONP callback
120. XSS via Angular template injection
121. XSS via React dangerouslySetInnerHTML
122. XSS via markdown rendering
123. XSS via CSP bypass (unsafe-inline, nonce reuse)
124. Self-XSS → CSRF chain (account takeover)
125. Blind XSS (payload fires in admin panel)

## Business Logic (30)
126. Price manipulation (negative price, zero price)
127. Quantity manipulation (negative quantity)
128. Currency confusion (pay in cheaper currency)
129. Coupon/discount stacking
130. Coupon reuse after expiry
131. Race condition on payment (double-spend)
132. Race condition on coupon redemption
133. Race condition on account creation (duplicate)
134. Race condition on withdrawal
135. Race condition on voting/likes
136. Referral abuse (self-referral)
137. Trial abuse (infinite free trials)
138. Subscription downgrade retains premium features
139. Order status manipulation (skip payment step)
140. Checkout flow bypass (skip to confirmation)
141. Gift card/credit generation
142. Loyalty points manipulation
143. Auction bid manipulation (bid below minimum)
144. Auction sniping via time manipulation
145. Inventory manipulation (oversell)
146. Shipping address swap after payment
147. Refund abuse (refund + keep item)
148. Fee bypass (avoid platform fees)
149. Withdrawal to unverified account
150. KYC bypass
151. Age verification bypass
152. Geo-restriction bypass for purchases
153. Rate limit bypass on financial operations
154. Integer overflow in balance/amount fields
155. Float precision abuse (0.000001 rounds to 0)

## File Upload (15)
156. Unrestricted file upload (PHP/JSP/ASPX webshell)
157. File upload bypass via double extension (.php.jpg)
158. File upload bypass via null byte (file.php%00.jpg)
159. File upload bypass via Content-Type manipulation
160. File upload bypass via magic bytes
161. SVG upload → XSS
162. SVG upload → SSRF
163. XML upload → XXE
164. ZIP upload → path traversal (zip slip)
165. Image upload → ImageTragick (CVE-2016-3714)
166. PDF upload → SSRF via annotations
167. DOCX upload → XXE
168. File upload → overwrite existing files
169. File upload → directory traversal in filename
170. Large file upload → DoS

## API-Specific (25)
171. GraphQL introspection enabled
172. GraphQL query depth abuse (nested queries)
173. GraphQL alias-based rate limit bypass
174. GraphQL batch query for brute-force
175. GraphQL mutation without authorization
176. REST API mass assignment via extra JSON fields
177. REST API verb tampering (GET → PUT/DELETE)
178. REST API parameter pollution
179. REST API JSON injection in string fields
180. API key in URL (leaked via Referer/logs)
181. API key with excessive permissions
182. API versioning bypass (v1 has weaker auth)
183. Webhook URL SSRF
184. Webhook secret in response
185. WebSocket auth bypass
186. WebSocket message injection
187. gRPC reflection enabled
188. gRPC auth bypass
189. OpenAPI/Swagger spec exposed with internal endpoints
190. Rate limit bypass via header rotation (X-Forwarded-For)
191. Rate limit bypass via API key rotation
192. Rate limit bypass via endpoint variation (/users vs /Users)
193. CORS misconfiguration (reflect origin + credentials)
194. CORS null origin bypass
195. HTTP request smuggling (CL.TE / TE.CL)

## Infrastructure & Cloud (20)
196. Subdomain takeover (dangling CNAME)
197. S3 bucket listing/write
198. Azure blob public access
199. GCS bucket public access
200. Exposed Kubernetes dashboard
201. Exposed Docker API
202. Exposed Redis/Memcached
203. Exposed Elasticsearch
204. Exposed MongoDB
205. Git repository exposed (.git/config)
206. Environment file exposed (.env)
207. Backup files exposed (.sql, .zip, .tar.gz)
208. Source maps exposed (.js.map)
209. Debug endpoints exposed (/debug, /trace, /actuator)
210. Admin panels without auth
211. CI/CD secrets in public repos
212. Terraform state file exposed
213. AWS credentials in source/config
214. Internal service exposed to internet
215. DNS zone transfer

## Mobile/Client-Side (10)
216. Hardcoded API keys in mobile app
217. Certificate pinning bypass
218. Insecure data storage (SharedPreferences/Keychain)
219. Deep link hijacking
220. Intent redirection (Android)
221. WebView JavaScript bridge exploitation
222. Binary patching (modify client-side checks)
223. API endpoint discovery from decompiled app
224. Token stored in logs
225. Clipboard data leakage
