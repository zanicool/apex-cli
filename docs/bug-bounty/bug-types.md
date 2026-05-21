# Bug Types Cheatsheet

Quick reference for the most profitable bug types in bug bounty hunting.

---

## 🥇 Tier 1: High ROI (Focus Here First)

### 1. IDOR (Insecure Direct Object Reference)

**What**: Access other users' data by changing IDs

**Where to find**:
- `/api/user/123` → try `/api/user/124`
- `/profile?id=456` → try different IDs
- `/order/789` → access other orders

**Test cases**:
```bash
# Original request
GET /api/user/123/profile

# Test with different ID
GET /api/user/124/profile

# Test with your ID on admin endpoint
GET /api/admin/user/123
```

**Typical payout**: €100-500

**Ask CPM**: `q chat "Show me 10 IDOR test cases for an e-commerce site"`

---

### 2. Broken Access Control

**What**: Access resources you shouldn't have permission for

**Where to find**:
- Admin panels without auth check
- Privilege escalation (user → admin)
- Horizontal access (user A → user B data)

**Test cases**:
```bash
# Try admin endpoints as regular user
GET /admin/dashboard
GET /api/admin/users

# Try changing role in request
POST /api/update-profile
{"role": "admin"}

# Try accessing other users' actions
POST /api/user/456/delete-account
```

**Typical payout**: €200-1000

**Ask CPM**: `q chat "What are common access control bypass techniques?"`

---

### 3. API Leaks

**What**: Sensitive data exposed through APIs

**Where to find**:
- Unauthenticated API endpoints
- Excessive data in responses
- Debug endpoints left enabled

**Test cases**:
```bash
# Test without authentication
GET /api/users (no auth header)
GET /api/config
GET /api/debug

# Check response for sensitive data
GET /api/user/me
# Look for: passwords, tokens, internal IDs, PII
```

**Typical payout**: €100-500

**Ask CPM**: `q chat "What sensitive data should I look for in API responses?"`

---

## 🥈 Tier 2: Medium ROI

### 4. XSS (Cross-Site Scripting)

**What**: Inject JavaScript that executes in victim's browser

**Types**:
- **Reflected**: Payload in URL, executes immediately
- **Stored**: Payload saved in DB, executes for all users
- **DOM-based**: Client-side JavaScript vulnerability

**Test cases**:
```bash
# Basic test
<script>alert(1)</script>

# Bypass filters
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
"><script>alert(1)</script>

# In different contexts
?search=<script>alert(1)</script>
?name=<img src=x onerror=alert(1)>
```

**Typical payout**: €50-300 (reflected), €200-800 (stored)

**Ask CPM**: `q chat "Show me XSS payloads for bypassing common filters"`

---

### 5. CSRF (Cross-Site Request Forgery)

**What**: Force user to perform unwanted actions

**Where to find**:
- State-changing actions without CSRF token
- Missing SameSite cookie attribute
- Token not validated properly

**Test cases**:
```bash
# Check if CSRF token is required
POST /api/change-email
{"email": "attacker@evil.com"}
# Try without CSRF token

# Check if token is validated
POST /api/change-password
{"csrf_token": "invalid"}
```

**Typical payout**: €100-400

**Ask CPM**: `q chat "How do I test for CSRF vulnerabilities?"`

---

### 6. Business Logic Flaws

**What**: Application logic that can be abused

**Examples**:
- Negative prices in shopping cart
- Race conditions in payment
- Coupon code reuse
- Referral bonus abuse

**Test cases**:
```bash
# Negative quantity
POST /api/cart/add
{"product_id": 123, "quantity": -1}

# Race condition
# Send 10 simultaneous requests to redeem same coupon

# Skip payment steps
POST /api/order/confirm (without payment)
```

**Typical payout**: €200-1000+

**Ask CPM**: `q chat "What are common business logic vulnerabilities in e-commerce?"`

---

## 🥉 Tier 3: Lower ROI (Learn Later)

### 7. Security Misconfiguration

**What**: Insecure default settings

**Examples**:
- Missing security headers
- Directory listing enabled
- Default credentials
- Exposed .git folder

**Test cases**:
```bash
# Check headers
curl -I https://target.com
# Look for missing: CSP, HSTS, X-Frame-Options

# Check for exposed files
GET /.git/config
GET /.env
GET /admin (default creds)
```

**Typical payout**: €50-200

---

### 8. Open Redirect

**What**: Redirect users to malicious sites

**Test cases**:
```bash
# Test redirect parameter
GET /redirect?url=https://evil.com
GET /login?next=https://evil.com
GET /out?target=//evil.com
```

**Typical payout**: €50-150

---

## 🎯 Quick Decision Tree

```
Found something? Ask yourself:

1. Can I access OTHER USERS' data?
   → YES: IDOR (High value!)
   
2. Can I do ADMIN actions as USER?
   → YES: Broken Access Control (High value!)
   
3. Can I see SENSITIVE data without auth?
   → YES: API Leak (High value!)
   
4. Can I inject JAVASCRIPT?
   → YES: XSS (Medium value)
   
5. Can I make USER do unwanted ACTION?
   → YES: CSRF (Medium value)
   
6. Can I abuse BUSINESS LOGIC?
   → YES: Business Logic (High value!)
```

---

## 📊 Bug Hunting Priority

**Spend your time**:
- 40% - IDOR testing
- 20% - Access control testing
- 20% - API security
- 10% - XSS
- 10% - Other

---

## 🔍 Where to Find Each Bug Type

| Bug Type | Best Targets | Tools |
|----------|--------------|-------|
| **IDOR** | APIs, user profiles, orders | Burp, manual testing |
| **Access Control** | Admin panels, APIs | Burp, role switching |
| **API Leaks** | REST/GraphQL APIs | Postman, Burp |
| **XSS** | Search, comments, profiles | Burp, XSStrike |
| **CSRF** | State-changing actions | Burp, manual testing |
| **Business Logic** | Checkout, payments, referrals | Manual testing |

---

## 💡 Pro Tips

1. **Start with IDOR** - Easiest to find, best payout
2. **Test APIs first** - More bugs than UI
3. **Think like attacker** - "What would I want to steal?"
4. **Chain bugs** - XSS + CSRF = higher payout
5. **Read other reports** - Learn from HackerOne Hacktivity

---

## 🎓 Learning Path

**Week 1**: IDOR only  
**Week 2**: Access Control  
**Week 3**: API Security  
**Week 4**: XSS + CSRF  
**Month 2+**: Business Logic  

---

## 📚 Ask CPM for Examples

```bash
# Get specific examples
q chat "Show me 5 real IDOR examples from HackerOne"
q chat "What are creative XSS bypass techniques?"
q chat "Explain business logic flaws in payment systems"

# Get test cases
q chat "Generate IDOR test cases for a banking app"
q chat "What should I test for broken access control?"

# Get help understanding
q chat "I found this, is it a valid bug? [describe]"
q chat "How do I explain the impact of this IDOR?"
```

---

**Remember**: Quality > Quantity. One good IDOR beats 10 low-severity findings!
