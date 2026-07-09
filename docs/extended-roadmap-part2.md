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
