# Bug Bounty Methodology

Professional workflow for finding high-value vulnerabilities.

---

## 🎯 The 4-Phase Approach

```
RECON (40%) → SCAN (10%) → TEST (40%) → REPORT (10%)
```

**Key insight**: Most beginners skip recon. Professionals spend 40% of time here.

---

## Phase 1: Reconnaissance (40% of time)

**Goal**: Map the entire attack surface

### Step 1: Subdomain Discovery (30 min)

```bash
# Find all subdomains
subfinder -d target.com -o subdomains.txt

# Check which are alive
cat subdomains.txt | httpx -o alive.txt

# Categorize by type
cat alive.txt | grep "api\." > api-endpoints.txt
cat alive.txt | grep "dev\." > dev-endpoints.txt
cat alive.txt | grep "staging\." > staging-endpoints.txt
```

**Ask CPM**: `q chat "Analyze my subdomain list and suggest which to test first"`

### Step 2: Historical Endpoints (15 min)

```bash
# Find old/forgotten endpoints
waybackurls target.com | sort -u > historical.txt

# Look for interesting patterns
cat historical.txt | grep -E "admin|api|dev|test|staging"
```

**Why this matters**: Old endpoints often have unpatched vulnerabilities.

### Step 3: Technology Stack (10 min)

```bash
# Identify technologies
whatweb target.com

# Check for known CVEs
nuclei -u target.com -t ~/nuclei-templates/cves/
```

### Step 4: Manual Exploration (30 min)

**Open Burp Suite and browse the app**:
- Create account
- Use all features
- Note interesting endpoints
- Check API calls in Burp history

**Ask CPM**: `q chat "I see these API endpoints in Burp, which should I test? [paste list]"`

---

## Phase 2: Fast Vulnerability Scan (10% of time)

**Goal**: Find low-hanging fruit quickly

### Quick Wins (15 min)

```bash
# Run Nuclei for known issues
nuclei -u target.com -severity critical,high

# Check for common misconfigs
nuclei -u target.com -t ~/nuclei-templates/exposures/
nuclei -u target.com -t ~/nuclei-templates/misconfiguration/
```

### Security Headers (5 min)

```bash
# Check headers
curl -I https://target.com

# Look for missing:
# - Content-Security-Policy
# - X-Frame-Options
# - Strict-Transport-Security
```

**Note**: These are usually low-severity, but quick to find.

---

## Phase 3: Deep Testing (40% of time)

**Goal**: Find high-value vulnerabilities

### 3A: IDOR Testing (60 min)

**This is where the money is!**

#### Step 1: Identify Endpoints with IDs

```bash
# From Burp history, find URLs like:
/api/user/123
/profile?id=456
/order/789
/document/abc-def-ghi
```

#### Step 2: Test Each Endpoint

```
1. Note your own ID (e.g., 123)
2. Create second test account (ID: 124)
3. Try accessing 124's data with 123's session
4. Try accessing 123's data with 124's session
```

#### Step 3: Test Variations

```bash
# Numeric IDs
/api/user/123 → /api/user/124

# UUIDs
/api/user/abc-123 → /api/user/def-456

# Encoded IDs
/api/user/MTIz → /api/user/MTI0 (base64)

# In different parameters
?user_id=123
?id=123
?uid=123
```

**Ask CPM**: `q chat "I found this endpoint: /api/user/123/orders - how should I test for IDOR?"`

### 3B: Access Control Testing (45 min)

#### Test 1: Horizontal Access

```
User A tries to access User B's resources
```

#### Test 2: Vertical Access

```
Regular user tries to access admin functions
```

#### Test 3: Missing Function Level Access Control

```bash
# Try admin endpoints as regular user
GET /api/admin/users
GET /api/admin/settings
POST /api/admin/delete-user

# Try changing role
POST /api/update-profile
{"role": "admin"}
```

**Ask CPM**: `q chat "What admin endpoints should I test on a typical web app?"`

### 3C: API Security Testing (30 min)

#### Test 1: Authentication

```bash
# Try without auth header
GET /api/users (remove Authorization header)

# Try with invalid token
GET /api/users
Authorization: Bearer invalid_token

# Try with expired token
GET /api/users
Authorization: Bearer <old_token>
```

#### Test 2: Excessive Data Exposure

```bash
# Check response for sensitive data
GET /api/user/me

# Look for:
# - Other users' data
# - Password hashes
# - API keys/tokens
# - Internal IDs
# - PII (SSN, credit cards)
```

#### Test 3: Mass Assignment

```bash
# Try adding extra fields
POST /api/update-profile
{
  "name": "Test",
  "email": "test@test.com",
  "role": "admin",        # Extra field
  "is_verified": true     # Extra field
}
```

**Ask CPM**: `q chat "What fields should I try in mass assignment attacks?"`

### 3D: XSS Testing (30 min)

#### Test in All Input Fields

```bash
# Basic payload
<script>alert(1)</script>

# Common bypasses
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><script>alert(1)</script>
javascript:alert(1)
```

#### Test in Different Contexts

```
1. URL parameters: ?search=<payload>
2. Form inputs: name, email, comment
3. Headers: User-Agent, Referer
4. JSON: {"name": "<payload>"}
```

**Ask CPM**: `q chat "The app filters <script> tags, what payloads should I try?"`

---

## Phase 4: Validation & Reporting (10% of time)

### Step 1: Reproduce (10 min)

**Test 3 times to confirm**:
1. Clear cookies, try again
2. Use different account
3. Use different browser

### Step 2: Assess Impact (5 min)

**Ask yourself**:
- Can attacker steal data?
- Can attacker modify data?
- Can attacker impersonate users?
- How many users affected?

**Ask CPM**: `q chat "I can access other users' orders, what's the severity?"`

### Step 3: Write Report (20 min)

**Use this template**:

```markdown
## Summary
[One sentence description]

## Vulnerability Details
- Type: IDOR
- Severity: High
- Endpoint: /api/user/{id}/orders

## Steps to Reproduce
1. Login as User A (ID: 123)
2. Send GET request to /api/user/124/orders
3. Observe: Can see User B's orders

## Proof of Concept
[Screenshot or curl command]

## Impact
Attacker can access any user's order history, including:
- Personal information
- Shipping addresses
- Purchase history

## Remediation
Implement proper authorization check:
- Verify requesting user owns the resource
- Use session user ID, not URL parameter
```

**Ask CPM**: `q chat "Review my bug report: [paste report]"`

---

## 🎯 Daily Workflow

### Morning Routine (30 min)

```bash
# 1. Pick target
echo "target.com" > today.txt

# 2. Quick recon
subfinder -d target.com | httpx > alive.txt

# 3. Review results
cat alive.txt
```

### Deep Work (2 hours)

```
Hour 1: IDOR testing on all endpoints
Hour 2: Access control + API testing
```

### Evening Review (15 min)

```bash
# Document findings
echo "2026-05-21 | target.com | Tested 15 endpoints | Found 1 IDOR" >> log.txt

# Ask CPM for feedback
q chat "I tested these endpoints today: [list]. What did I miss?"
```

---

## 🧠 Mental Models

### Model 1: Think Like an Attacker

**Don't ask**: "Does this work as designed?"  
**Ask**: "How can I abuse this?"

### Model 2: Follow the Data

```
User Input → Processing → Storage → Output
```

**Test at each stage**:
- Input: Can I inject malicious data?
- Processing: Can I bypass validation?
- Storage: Can I access other users' data?
- Output: Is data properly sanitized?

### Model 3: Trust Boundaries

**Every time data crosses a boundary, test**:
- Client → Server
- User → Admin
- Public → Private
- Unauthenticated → Authenticated

**Ask CPM**: `q chat "Explain trust boundaries in web applications"`

---

## 🚫 Common Mistakes to Avoid

### Mistake 1: Only Testing UI

**Wrong**: Click through website  
**Right**: Intercept with Burp, test APIs directly

### Mistake 2: Giving Up Too Fast

**Wrong**: "Nuclei found nothing, moving on"  
**Right**: Manual testing finds 80% of high-value bugs

### Mistake 3: Ignoring Recon

**Wrong**: Jump straight to testing homepage  
**Right**: Find dev.target.com with outdated code

### Mistake 4: Not Testing Thoroughly

**Wrong**: Test one endpoint for IDOR  
**Right**: Test ALL endpoints with IDs

**Ask CPM**: `q chat "Am I making any of these common mistakes?"`

---

## 📊 Time Allocation (Per Target)

```
Recon:           2 hours (40%)
Fast Scan:       30 min  (10%)
IDOR Testing:    1.5 hours (30%)
Other Testing:   30 min  (10%)
Reporting:       30 min  (10%)
---
Total:           5 hours
```

**Adjust based on target size**

---

## 🎓 Skill Progression

### Beginner (Month 1)
- Follow this methodology exactly
- Focus on IDOR only
- Test 1 target thoroughly

### Intermediate (Month 2-3)
- Add access control testing
- Test 2-3 targets per week
- Start finding patterns

### Advanced (Month 4+)
- Develop your own methodology
- Spot vulnerabilities quickly
- Focus on business logic

**Ask CPM**: `q chat "What skill level am I at based on my findings?"`

---

## 🔄 Continuous Improvement

### After Each Target

**Ask yourself**:
1. What worked well?
2. What did I miss?
3. What should I try next time?

**Ask CPM**:
```bash
q chat "Review my methodology for target.com: [describe what you did]"
q chat "What should I improve in my testing approach?"
```

### Weekly Review

```bash
# Analyze your log
cat log.txt | grep "Found"

# Ask CPM
q chat "Analyze my weekly log: [paste log]. What patterns do you see?"
```

---

## 🎯 Quick Reference

**Starting a new target?**

```bash
# 1. Recon
subfinder -d target.com | httpx > alive.txt
waybackurls target.com > historical.txt

# 2. Browse with Burp
# (Manual exploration)

# 3. Test IDOR on every endpoint with ID
# (Manual testing)

# 4. Document findings
echo "Date | Target | Findings" >> log.txt
```

**Stuck? Ask CPM**:
```bash
q chat "I'm stuck on target.com, what should I try?"
q chat "I found nothing after 2 hours, what am I missing?"
```

---

**Remember**: Methodology > Tools. Follow the process, results will come!
