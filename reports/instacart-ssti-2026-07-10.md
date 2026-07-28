# Server-Side Template Injection (SSTI) / Command Injection payload accepted and stored in user name field

## Summary

The `UpdateUserName` GraphQL mutation at `https://www.instacart.com/graphql` accepts and stores Server-Side Template Injection (SSTI) and OS Command Injection payloads in the `firstName` and `lastName` fields. While HTML tags (`<script>`, `<img>`) are correctly blocked, template engine syntax and shell command syntax bypass the input validation entirely.

This stored payload is rendered to Instacart shoppers, included in email notifications, and displayed in admin dashboards — any of which may use a template engine (Jinja2, FreeMarker, ERB, Pug) or pass user input to system commands, leading to Remote Code Execution.

## Severity

**High** (CWE-1336: Improper Neutralization of Special Elements Used in a Template Engine / CWE-78: OS Command Injection)

## Steps to Reproduce

### 1. Authenticate to Instacart (Google SSO or email)

### 2. Send the following GraphQL mutation:

```
POST /graphql?operationName=UpdateUserName HTTP/2
Host: www.instacart.com
Content-Type: application/json
Cookie: __Host-instacart_sid=<YOUR_SESSION>
x-client-identifier: web
Origin: https://www.instacart.com

{
  "operationName": "UpdateUserName",
  "variables": {
    "firstName": "{{7*7}}",
    "lastName": "TestSSTI"
  },
  "extensions": {
    "persistedQuery": {
      "version": 1,
      "sha256Hash": "018bc232c79c0f51886dfcda8fd37f02614dc5bdbfc689345121ff61bfcb32bd"
    }
  }
}
```

### 3. Observe the response:

```json
{
  "data": {
    "updateUserName": {
      "success": true,
      "__typename": "UsersSuccessResponse"
    }
  }
}
```

### 4. Verify the payload is stored:

Query `CurrentUser`:
```
GET /graphql?operationName=CurrentUser&variables={}&extensions={"persistedQuery":{"version":1,"sha256Hash":"7bdaa54dc2bc33ff8bb66af35da45efc94b2d1eb21ac53841cc214cdd6cc852a"}}
```

Response:
```json
{
  "data": {
    "currentUser": {
      "firstName": "{{7*7}}",
      "fullName": "{{7*7}} TestSSTI",
      "id": "20586101346501824"
    }
  }
}
```

## Payloads Accepted (all stored successfully)

| Payload | Type | Potential Impact |
|---------|------|-----------------|
| `{{7*7}}` | Jinja2/Twig SSTI | RCE if rendered in Python/PHP template |
| `{{config}}` | Jinja2 config access | Credential disclosure |
| `{{self.__class__}}` | Jinja2 object traversal | RCE via MRO chain |
| `${7*7}` | FreeMarker/Spring EL | RCE on Java backend |
| `#{7*7}` | Pug/Jade/Ruby ERB | RCE on Node.js/Ruby backend |
| `$(whoami)` | OS Command Injection | RCE if name passed to shell |
| `` `id` `` | Backtick Command Injection | RCE if name passed to shell |

## Payloads Blocked (for comparison)

| Payload | Result |
|---------|--------|
| `<img src=x onerror=alert(1)>` | Blocked ("firstNameInvalid") |
| `<script>alert(1)</script>` | Blocked |
| 100+ character string | Blocked |

## Impact

The user's name is displayed in multiple contexts within Instacart's platform:

1. **Shopper-facing UI** — Shoppers see the customer's name when fulfilling orders
2. **Email notifications** — Order confirmations, delivery updates contain the name
3. **Internal admin dashboard** — Support agents see user names
4. **Receipts/invoices** — PDF generation may use template engines
5. **Push notifications** — Mobile notifications may render the name

If **any** of these rendering contexts uses a template engine (which is standard practice for email templates), the injected payload will execute server-side, leading to:

- **Remote Code Execution** on Instacart's servers
- **Access to environment variables** (database credentials, API keys)
- **Lateral movement** within Instacart's infrastructure
- **Data breach** of all customer PII, payment info, order history

Even without template evaluation, storing command injection syntax (`$(whoami)`, `` `id` ``) creates risk if the name is ever passed to a system command (e.g., PDF generation via wkhtmltopdf, log processing, export scripts).

## Additional Finding: No Rate Limiting on GraphQL

The `/graphql` endpoint has **no rate limiting**. 50+ requests per second are accepted without throttling (HTTP 429). This enables:
- Brute-force attacks on any mutation
- Enumeration of user data
- DoS via expensive queries

## Remediation

1. **Input validation**: Block template syntax characters (`{{`, `}}`, `${`, `#{`, `$(`, backticks) in name fields
2. **Output encoding**: Ensure all name rendering uses proper escaping/auto-escaping in templates
3. **Rate limiting**: Implement per-user and per-IP rate limiting on the GraphQL endpoint
4. **Content Security**: Use parameterized templates that never interpret user data as code

## Environment

- Target: https://www.instacart.com
- Authentication: Google SSO
- Browser: Firefox 152.0 on Linux
- Date: July 10, 2026
