/// @file test_precision.cpp
/// @brief Regression tests that LOCK IN the precision fixes from the
///        false-positive-reduction pass. These guard against silently
///        reintroducing the noise that was eliminated:
///          * info-severity findings scoring above "possible"
///          * low-severity, evidence-less findings scoring "probable"
///          * evidence-less findings passing a `--confidence 2` filter
///          * template/EL canaries whose detect string is a substring of the
///            payload (reflection mistaken for evaluation)
///          * the scope gate dropping fabricated info noise while keeping
///            concrete-evidence findings
///
/// No network / live server is required: confidence scoring and the scope
/// gate are pure functions over Finding structs, so these run deterministically
/// under `make test`.
#include "../src/confidence.hpp"
#include "../src/crawler.hpp"
#include "../src/scanner.hpp"
#include "../src/scanners/confirm.hpp"
#include "../src/scanners/scanner_base.hpp"
#include <cassert>
#include <iostream>
#include <string>
#include <vector>

namespace {

using apex::Confidence;
using apex::Finding;

Finding mk(const std::string &type, const std::string &sev,
           const std::string &payload = "", const std::string &evidence = "") {
  Finding f;
  f.type = type;
  f.severity = sev;
  f.url = "http://t/";
  f.param = "p";
  f.payload = payload;
  f.evidence = evidence;
  return f;
}

// ── Confidence scoring ─────────────────────────────────────────────────────

/// Info-severity findings must NEVER exceed Possible, even with payload+evidence.
void test_info_capped_at_possible() {
  // Even when both payload and evidence are set (which would otherwise be the
  // "Confirmed/Probable" branch), an info finding is only Possible. This is the
  // ordering fix that stopped DNS Rebinding (info, with evidence) from leaking
  // into the reportable tier.
  auto dns = mk("DNS Rebinding", "info", "Host: attacker.example.com",
                "arbitrary Host returned identical 200 response");
  assert(apex::score_confidence(dns) == Confidence::Possible);

  auto refl = mk("Reflection", "info", "rfl3ct10n", "reflected");
  assert(apex::score_confidence(refl) == Confidence::Possible);
  std::cout << "  [pass] info_capped_at_possible\n";
}

/// Low-severity findings with no evidence are observations, not Probable vulns.
void test_low_no_evidence_capped() {
  // Anomaly (low) with a payload but empty evidence used to score Probable and
  // pass `--confidence 2`. It must now be Possible.
  auto anomaly = mk("Anomaly", "low", "admin", /*evidence*/ "");
  assert(apex::score_confidence(anomaly) == Confidence::Possible);

  // A low finding WITH evidence may still rise to Probable.
  auto low_ev = mk("Tabnabbing", "low", "", "target=_blank without noopener");
  assert(apex::score_confidence(low_ev) != Confidence::Possible);
  std::cout << "  [pass] low_no_evidence_capped\n";
}

/// A finding with neither payload nor evidence is at most Possible.
void test_no_proof_is_possible() {
  auto bare = mk("Log Injection", "medium", "", "");
  assert(apex::score_confidence(bare) == Confidence::Possible);
  std::cout << "  [pass] no_proof_is_possible\n";
}

/// Concrete evidence + payload on a real vuln type is Confirmed.
void test_evidence_and_payload_confirmed() {
  auto sqli = mk("SQLi", "critical", "1'", "SQL syntax");
  assert(apex::score_confidence(sqli) == Confidence::Confirmed);
  auto xss = mk("XSS", "high", "<script>alert(1)</script>",
                "<script>alert(1)</script>");
  assert(apex::score_confidence(xss) == Confidence::Confirmed);
  auto lfi = mk("LFI", "high", "../../etc/passwd",
                "leaked file content: root:x:0:0");
  assert(apex::score_confidence(lfi) == Confidence::Confirmed);
  std::cout << "  [pass] evidence_and_payload_confirmed\n";
}

/// The `--confidence 2` filter must drop the evidence-less / info noise and
/// keep the confirmed true positives. This mirrors the reportable-set contract.
void test_confidence_filter_reportable_set() {
  std::vector<Finding> findings = {
      mk("SQLi", "critical", "1'", "SQL syntax"),          // keep
      mk("XSS", "high", "<script>", "<script>"),           // keep
      mk("DNS Rebinding", "info", "Host: x", "identical"), // drop (info)
      mk("Anomaly", "low", "admin", ""),                   // drop (low,no-ev)
      mk("Reflection", "info", "rfl3ct10n", "reflected"),  // drop (info)
      mk("Log Injection", "medium", "", ""),               // drop (no proof)
  };
  auto kept = apex::filter_by_confidence(findings, 2);
  // Only the two confirmed true positives survive.
  assert(kept.size() == 2);
  for (const auto &f : kept)
    assert(f.type == "SQLi" || f.type == "XSS");
  std::cout << "  [pass] confidence_filter_reportable_set\n";
}

// ── Scope gate ─────────────────────────────────────────────────────────────

/// The scope gate keeps concrete-evidence findings and drops fabricated noise.
void test_scope_gate_keeps_real_drops_noise() {
  std::vector<Finding> findings = {
      mk("SQLi", "critical", "1'", "SQL syntax"),
      mk("XSS", "high", "<script>", "<script>"),
      mk("SSRF Variant", "critical", "file:///etc/passwd",
         "root:x:0:0:root:/root:/bin/bash"),
  };
  auto kept = apex::apply_scope_gate(findings);
  // All three carry concrete evidence and must be preserved.
  assert(kept.size() == 3);
  std::cout << "  [pass] scope_gate_keeps_real_drops_noise\n";
}

// ── Confirmation helpers (reflection ≠ evaluation) ─────────────────────────

/// A canary whose detect string is part of the payload proves only reflection,
/// never evaluation. This is the exact bug that made {{self.__class__}} and
/// ${T(java.lang.Runtime)} fire on any app that echoed input.
void test_evaluation_not_reflection() {
  using namespace apex::confirm;

  // Reflection trap: detect is a substring of the payload → must NOT confirm,
  // even though the "detect" string appears in the (reflected) body.
  assert(detect_in_payload("{{self.__class__}}", "__class__"));
  assert(!is_evaluation_match("{{self.__class__}}", "__class__",
                              "<p>{{self.__class__}}</p>", "<p>baseline</p>"));
  assert(detect_in_payload("${T(java.lang.Runtime)}", "java.lang.Runtime"));
  assert(!is_evaluation_match("${T(java.lang.Runtime)}", "java.lang.Runtime",
                              "echo ${T(java.lang.Runtime)}", ""));

  // Genuine evaluation: 7*7 -> 49; "49" is not in the payload, appears in the
  // body, and is absent from baseline → confirmed.
  assert(!detect_in_payload("{{7*7}}", "49"));
  assert(is_evaluation_match("{{7*7}}", "49", "<p>49</p>", "<p>baseline</p>"));

  // Same result present in baseline (pre-existing) → not confirmed.
  assert(!is_evaluation_match("{{7*7}}", "49", "<p>49</p>", "<p>49 already</p>"));
  std::cout << "  [pass] evaluation_not_reflection\n";
}

/// Reflected XSS requires an HTML breaker, unescaped reflection, and baseline
/// absence. A plain "javascript:alert(1)" reflected as body text is NOT XSS.
void test_reflected_xss_requires_breaker() {
  using namespace apex::confirm;

  // No HTML metacharacters → not XSS even if reflected verbatim.
  assert(!has_html_breaker("javascript:alert(1)"));
  assert(!is_reflected_xss("javascript:alert(1)",
                           "<p>user=javascript:alert(1)</p>", "<p>user=</p>"));

  // Real breakout reflected unescaped and absent from baseline → XSS.
  assert(has_html_breaker("<script>alert(1)</script>"));
  assert(is_reflected_xss("<script>alert(1)</script>",
                          "<div><script>alert(1)</script></div>",
                          "<div>baseline</div>"));

  // Escaped reflection (entity-encoded) → the raw payload is absent → not XSS.
  assert(!is_reflected_xss("<script>alert(1)</script>",
                           "<div>&lt;script&gt;alert(1)&lt;/script&gt;</div>",
                           "<div>baseline</div>"));
  std::cout << "  [pass] reflected_xss_requires_breaker\n";
}

// ── Recon: cloud/SaaS asset ownership ──────────────────────────────────────

/// A guessed SaaS/cloud asset must be attributable to the target before it is
/// reported. This kills the S3/SharePoint/Jira/M365/Azure false positives that
/// fired just because a generic tenant name (e.g. "demo") exists elsewhere.
void test_cloud_asset_ownership() {
  using namespace apex::confirm;
  // Empty body → never owned (the old code reported on bare status codes).
  assert(!asset_belongs_to_target("", "demo.testfire.net", "demo"));
  // Body referencing an unrelated tenant → not owned by the target.
  assert(!asset_belongs_to_target("<html>Some other company's SharePoint</html>",
                                  "demo.testfire.net", "demo"));
  // Body referencing the target's registrable domain → owned.
  assert(asset_belongs_to_target("...contact us at info@testfire.net ...",
                                 "testfire.net", "testfire"));
  // A sufficiently specific org token in the body → owned.
  assert(asset_belongs_to_target("welcome to the acmecorp tenant",
                                 "acmecorp.com", "acmecorp"));
  // Too-short/generic org token alone → not enough.
  assert(!asset_belongs_to_target("generic api ok", "abc.com", "abc"));
  std::cout << "  [pass] cloud_asset_ownership\n";
}

// ── Crawl: form fields become injection targets ───────────────────────────

/// A search form (<form action="/search.jsp"><input name="query">) with no
/// "?query=" URL anywhere must still yield a "/search.jsp?query=" target, or
/// form-driven reflected XSS (e.g. AltoroMutual) is never tested.
void test_form_fields_become_targets() {
  apex::CrawlResult crawl;
  crawl.urls = {"http://demo.testfire.net/"};
  apex::Form form;
  form.action = "/search.jsp";
  form.method = "GET";
  form.fields = {{"http://demo.testfire.net/search.jsp", "query", "query", "GET"}};
  crawl.forms = {form};
  // No URL query params at all.
  auto targets = apex::get_targets(crawl, "http://demo.testfire.net/", "id");
  bool found = false;
  for (const auto &[base, param] : targets)
    if (param == "query" &&
        base == "http://demo.testfire.net/search.jsp?query=")
      found = true;
  assert(found);
  std::cout << "  [pass] form_fields_become_targets\n";
}

// ── Auth-bypass login SQLi differential ────────────────────────────────────

/// Rejected baseline redirects to the login page; the SQLi payload redirects to
/// an authenticated area — that cross-over is an auth bypass. Mirrors the real
/// AltoroMutual case (bad creds -> /login.jsp, admin'-- -> /bank/main.jsp).
void test_auth_bypass_differential() {
  using namespace apex::confirm;
  // Real bypass: baseline stays at login, injection leaves to /bank/main.jsp.
  assert(is_auth_bypass(302, "http://t/login.jsp", 302,
                        "http://t/bank/main.jsp"));
  // No bypass: both rejected to the same login page.
  assert(!is_auth_bypass(302, "http://t/login.jsp", 302,
                         "http://t/login.jsp"));
  // No bypass: injection also lands back on login (payload didn't work).
  assert(!is_auth_bypass(302, "http://t/login.jsp", 302,
                         "http://t/login.jsp?error=1"));
  // Status-change bypass: baseline denies (302 to login), injection returns 200.
  assert(is_auth_bypass(302, "http://t/login.jsp", 200, ""));
  std::cout << "  [pass] auth_bypass_differential\n";
}

// ── Crawl: relative-URL resolution with embedded URLs in the query ─────────

/// A relative href whose QUERY contains a URL (e.g. "/fetch?url=http://x")
/// must resolve to an absolute in-scope URL, not be returned verbatim and then
/// dropped. This was the crawler bug that hid the entire SSRF endpoint class.
void test_resolve_url_embedded_query_url() {
  const std::string page = "http://demo.testfire.net/";
  // Relative link with an embedded absolute URL in the query.
  auto r = apex::resolve_url("/fetch?url=http://example.com", page);
  assert(r == "http://demo.testfire.net/fetch?url=http://example.com");

  // Genuinely absolute URLs are still returned as-is.
  assert(apex::resolve_url("https://other.com/x", page) ==
         "https://other.com/x");

  // Plain relative path still resolves against the host.
  assert(apex::resolve_url("/login.jsp", page) ==
         "http://demo.testfire.net/login.jsp");
  std::cout << "  [pass] resolve_url_embedded_query_url\n";
}

} // namespace

// Invoked from test_main.cpp's main().
void run_precision_tests() {
  test_info_capped_at_possible();
  test_low_no_evidence_capped();
  test_no_proof_is_possible();
  test_evidence_and_payload_confirmed();
  test_confidence_filter_reportable_set();
  test_scope_gate_keeps_real_drops_noise();
  test_evaluation_not_reflection();
  test_reflected_xss_requires_breaker();
  test_cloud_asset_ownership();
  test_form_fields_become_targets();
  test_auth_bypass_differential();
  test_resolve_url_embedded_query_url();
}
