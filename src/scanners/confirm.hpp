/// @file confirm.hpp
/// @brief Centralized confirmation predicates shared by scanners.
///
/// These encode the precision invariants learned during the
/// false-positive-reduction pass, in ONE place, so the whole "reflection is not
/// proof" class of bugs cannot silently reappear scanner-by-scanner:
///
///   * A template/EL/formula canary only proves EVALUATION when its detect
///     string is absent from the payload itself. If the detect string is a
///     substring of the payload, an app that merely reflects input unescaped
///     will match — a false positive. Use is_evaluation_match().
///
///   * Reflected XSS in HTML body context requires the payload to carry an
///     active HTML metacharacter (< > ") and to reflect unescaped and to be
///     absent from a benign baseline. Use is_reflected_xss().
///
/// All predicates are pure and header-only so they are unit-testable without a
/// live server (see tests/test_precision.cpp).
#ifndef APEX_CONFIRM_HPP
#define APEX_CONFIRM_HPP

#include <string>

namespace apex {
namespace confirm {

/// True when `detect` is a substring of `payload`. Such a canary can only ever
/// prove reflection, never evaluation, and must not be used to confirm SSTI /
/// EL / formula injection.
inline bool detect_in_payload(const std::string &payload,
                              const std::string &detect) {
  return !detect.empty() && payload.find(detect) != std::string::npos;
}

/// True when the canary genuinely proves server-side EVALUATION:
///   - the detect string is NOT part of the payload (else it is reflection), and
///   - the detect string appears in the response body, and
///   - it does not appear in the benign baseline body.
inline bool is_evaluation_match(const std::string &payload,
                                const std::string &detect,
                                const std::string &body,
                                const std::string &baseline_body) {
  if (detect_in_payload(payload, detect)) return false;      // reflection, not eval
  if (body.find(detect) == std::string::npos) return false;  // no result
  if (baseline_body.find(detect) != std::string::npos)       // pre-existing
    return false;
  return true;
}

/// True when `payload` carries an active HTML-breaking metacharacter that could
/// escape body/text context into markup.
inline bool has_html_breaker(const std::string &payload) {
  return payload.find('<') != std::string::npos ||
         payload.find('>') != std::string::npos ||
         payload.find('"') != std::string::npos;
}

/// True when the payload constitutes a confirmed reflected XSS in HTML body
/// context: it must carry an HTML breaker, reflect unescaped in the response,
/// and be absent from the benign baseline.
inline bool is_reflected_xss(const std::string &payload,
                             const std::string &body,
                             const std::string &baseline_body) {
  if (!has_html_breaker(payload)) return false;
  if (body.find(payload) == std::string::npos) return false;
  if (baseline_body.find(payload) != std::string::npos) return false;
  return true;
}

/// True when a discovered cloud/SaaS asset (guessed from the target's name,
/// e.g. `<org>.sharepoint.com`, `<org>.s3.amazonaws.com`, `<org>.atlassian.net`)
/// can be attributed to the TARGET — not merely to some unrelated tenant that
/// happens to share a common name like "demo", "app" or "portal".
///
/// A bare 200/403 on a guessed generic name is NOT proof of ownership: generic
/// tenant names exist and belong to other parties. We require the response body
/// to reference the target's own identity (its registrable domain or org token)
/// before attributing the asset to the target.
///
/// @param resp_body  body returned by the guessed SaaS/cloud endpoint
/// @param target_domain  the full target host, e.g. "demo.testfire.net"
/// @param org  the org token guessed from the domain, e.g. "demo"
inline bool asset_belongs_to_target(const std::string &resp_body,
                                    const std::string &target_domain,
                                    const std::string &org) {
  if (resp_body.empty()) return false;
  // The registrable domain (e.g. "testfire.net") appearing in the asset body
  // is strong ownership evidence; a bare org token ("demo") is too generic to
  // count on its own, so we require the full domain.
  if (!target_domain.empty() &&
      resp_body.find(target_domain) != std::string::npos)
    return true;
  // Also accept the org token only when it is reasonably specific (>= 5 chars),
  // to avoid matching ubiquitous short names.
  if (org.size() >= 5 && resp_body.find(org) != std::string::npos)
    return true;
  return false;
}

/// True when a login POST with a SQL-injection payload produces an
/// AUTHENTICATION BYPASS relative to a rejected baseline: the injected request
/// lands somewhere the rejected request does not (a different 3xx redirect
/// target, or a different status), crossing from "login rejected" to "logged
/// in". This detects auth-bypass SQLi (e.g. uid=admin'-- → 302 /bank/main.jsp
/// whereas bad creds → 302 /login.jsp) which error-string GET scanners miss.
///
/// @param base_status   status code of the rejected-baseline login POST
/// @param base_location Location header of the rejected baseline (may be empty)
/// @param atk_status    status code of the SQLi login POST
/// @param atk_location  Location header of the SQLi login POST (may be empty)
/// @param login_markers substrings that indicate a login/rejection page
inline bool is_auth_bypass(int base_status, const std::string &base_location,
                           int atk_status, const std::string &atk_location) {
  // Both must be redirects for a Location comparison to be meaningful; a
  // status-only change (e.g. 302 vs 200) is also a valid bypass signal.
  if (base_status != atk_status) {
    // A move from a redirect/deny to a 200 (or vice-versa) indicates the app
    // treated the injected credentials differently.
    return true;
  }
  if (base_location.empty() || atk_location.empty())
    return false;
  if (base_location == atk_location)
    return false;
  // Same status, but the injected request redirects ELSEWHERE than the reject
  // baseline — and specifically NOT back to a login page. The baseline points
  // at the login/error page; the attack pointing somewhere else means bypass.
  bool base_is_login =
      base_location.find("login") != std::string::npos ||
      base_location.find("signin") != std::string::npos ||
      base_location.find("error") != std::string::npos;
  bool atk_is_login =
      atk_location.find("login") != std::string::npos ||
      atk_location.find("signin") != std::string::npos ||
      atk_location.find("error") != std::string::npos;
  // Bypass when baseline stays at login but the attack leaves it.
  return base_is_login && !atk_is_login;
}

} // namespace confirm
} // namespace apex

#endif // APEX_CONFIRM_HPP
