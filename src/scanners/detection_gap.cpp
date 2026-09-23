/// @file scanners/detection_gap.cpp
/// @brief Scanners for gaps found in vulnerability battery testing:
///        SSTI (improved), NoSQL Injection, IDOR, CORS (improved),
///        Secrets/Credentials in responses.
#include <regex>
#include <set>
#include <sstream>

#include "counterfactual.hpp"
#include "scanner_base.hpp"

namespace apex {
namespace {

/// Improved SSTI: also probes common param names on all crawled URLs.
std::vector<Finding> scan_ssti_deep(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  const std::vector<std::pair<std::string, std::string>> payloads = {
      {"{{7*7}}", "49"}, {"${7*7}", "49"}, {"<%= 7*7 %>", "49"}, {"{{config}}", "SECRET"}, {"{{self.__class__}}", "__class__"},
  };
  const std::vector<std::string> ssti_params = {"name", "template", "input", "msg", "text", "content"};

  for (const auto& url : crawl.urls) {
    // Try discovered params first
    std::vector<std::pair<std::string, std::string>> targets;
    for (const auto& p : crawl.params) {
      if (p.url == url) targets.push_back({p.url + "?" + p.name + "=", p.name});
    }
    // Also try common SSTI param names
    for (const auto& pname : ssti_params) {
      targets.push_back({url + "?" + pname + "=", pname});
    }

    for (const auto& [base, param] : targets) {
      auto baseline = http.get(base + "test123xyz");
      for (const auto& [payload, detect] : payloads) {
        auto resp = http.get(base + payload);
        if (resp.body.find(detect) != std::string::npos && baseline.body.find(detect) == std::string::npos) {
          findings.push_back({"SSTI", "critical", url, "Server-Side Template Injection", param, payload, detect});
          goto next_url;  // one finding per URL is enough
        }
      }
    }
  next_url:;
  }
  return findings;
}

/// NoSQL Injection: MongoDB operator injection.
std::vector<Finding> scan_nosql(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  const std::vector<std::string> payloads = {"[$ne]=x", "[$gt]=", "[$regex]=.*", "{\"$ne\":\"\"}", "{\"$gt\":\"\"}"};
  const std::vector<std::string> indicators = {"admin", "superuser", "root", "username", "email"};

  for (const auto& url : crawl.urls) {
    auto targets = get_targets(crawl, url, "username");
    for (const auto& [base, param] : targets) {
      auto baseline = http.get(base + "normalvalue123");
      for (const auto& payload : payloads) {
        auto resp = http.get(base + payload);
        if (resp.status_code == 200 && resp.body.size() > baseline.body.size() && contains_any(resp.body, indicators) &&
            !contains_any(baseline.body, indicators)) {
          findings.push_back({"NoSQL Injection", "critical", url, "MongoDB operator injection", param, payload, resp.body.substr(0, 200)});
          goto next_nosql;
        }
      }
    }
  next_nosql:;
  }
  return findings;
}

/// IDOR: Insecure Direct Object Reference via sequential ID enumeration.
std::vector<Finding> scan_idor(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;

  // PII indicators — only flag IDOR if response contains private user data
  const std::vector<std::string> pii_indicators = {
      "\"email\"",   "\"phone\"",         "\"address\"",         "\"ssn\"",          "\"password\"", "\"credit_card\"", "\"card_number\"",
      "\"dob\"",     "\"date_of_birth\"", "\"social_security\"", "\"bank_account\"", "\"private\"",  "\"booking\"",     "\"order_total\"",
      "\"payment\"", "\"billing\"",       "@gmail.com",          "@yahoo.com",       "@hotmail.com", "@outlook.com"};

  // Look for URLs with numeric IDs
  std::regex id_re(R"([\?&](id|user_id|uid|account|profile)=(\d+))");

  for (const auto& url : crawl.urls) {
    std::smatch m;
    if (!std::regex_search(url, m, id_re)) continue;

    std::string param = m[1].str();
    int id = std::stoi(m[2].str());
    std::string base_path = url.substr(0, url.find('?')) + "?" + param + "=";

    // Get response for current ID
    auto resp1 = http.get(base_path + std::to_string(id));
    if (resp1.status_code != 200) continue;

    // Try adjacent IDs — if we get different data with PII, IDOR likely
    for (int other : {id + 1, id - 1, id + 100}) {
      if (other <= 0) continue;
      auto resp2 = http.get(base_path + std::to_string(other));
      if (resp2.status_code == 200 && !resp2.body.empty() && resp2.body != resp1.body && resp2.body.size() > 10) {
        // Check if response contains PII — not just different public data
        bool has_pii = contains_any(resp2.body, pii_indicators);
        if (has_pii) {
          findings.push_back({"IDOR", "high", url, "Private user data accessible via sequential ID", param, std::to_string(other),
                              "Response contains PII for ID " + std::to_string(other)});
          break;
        }
      }
    }
  }

  // Also check /users/1, /users/2 style paths
  for (const auto& url : crawl.urls) {
    std::regex path_id_re(R"((/(?:users?|profiles?|accounts?|orders?)/)\d+)");
    std::smatch m;
    if (!std::regex_search(url, m, path_id_re)) continue;
    std::string prefix = url.substr(0, url.find(m[1].str()) + m[1].str().size());
    auto r1 = http.get(prefix + "1");
    auto r2 = http.get(prefix + "2");
    if (r1.status_code == 200 && r2.status_code == 200 && r1.body != r2.body && r1.body.size() > 10 && r2.body.size() > 10) {
      // Only flag if responses contain PII
      bool r1_pii = contains_any(r1.body, pii_indicators);
      bool r2_pii = contains_any(r2.body, pii_indicators);
      if (r1_pii || r2_pii) {
        findings.push_back({"IDOR", "high", url, "Enumerable resource path exposes private data", "path_id", "1,2",
                            "Both IDs return PII-containing responses"});
      }
    }
  }
  return findings;
}

/// Improved CORS: test origin reflection and null origin.
std::vector<Finding> scan_cors_deep(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  // Test a subset of URLs (max 20)
  size_t limit = std::min(crawl.urls.size(), size_t(20));
  for (size_t i = 0; i < limit; ++i) {
    const auto& url = crawl.urls[i];

    // Test 1: reflected origin
    auto resp = http.get(url, {{"Origin", "https://evil.com"}});
    auto acao = resp.headers.find("Access-Control-Allow-Origin");
    if (acao != resp.headers.end()) {
      if (acao->second == "https://evil.com") {
        auto acac = resp.headers.find("Access-Control-Allow-Credentials");
        std::string sev = (acac != resp.headers.end() && acac->second == "true") ? "critical" : "high";
        findings.push_back({"CORS Misconfiguration", sev, url, "Origin reflected: " + acao->second, "", "",
                            "Access-Control-Allow-Origin: " + acao->second});
        continue;
      }
      if (acao->second == "*") {
        findings.push_back(
            {"CORS Misconfiguration", "medium", url, "Wildcard CORS allows any origin", "", "", "Access-Control-Allow-Origin: *"});
        continue;
      }
    }

    // Test 2: null origin
    resp = http.get(url, {{"Origin", "null"}});
    acao = resp.headers.find("Access-Control-Allow-Origin");
    if (acao != resp.headers.end() && acao->second == "null") {
      findings.push_back({"CORS Misconfiguration", "high", url, "Null origin accepted", "", "null", "Access-Control-Allow-Origin: null"});
    }
  }
  return findings;
}

/// Secrets/Credentials in responses: scan response bodies for leaked secrets.
std::vector<Finding> scan_response_secrets(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  struct SecretPattern {
    std::string name;
    std::regex re;
    std::string severity;
  };
  std::vector<SecretPattern> patterns = {
      {"AWS Access Key", std::regex(R"(AKIA[0-9A-Z]{16})"), "critical"},
      {"AWS Secret Key", std::regex(R"((?:aws_secret|secret_key|AWS_SECRET)[^=]*=\s*[A-Za-z0-9/+=]{40})"), "critical"},
      {"Generic API Key", std::regex(R"((?:api[_-]?key|apikey|api_secret)\s*[:=]\s*["']?[A-Za-z0-9_\-]{20,})"), "high"},
      {"Private Key", std::regex(R"(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)"), "critical"},
      {"JWT Token", std::regex(R"(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"), "high"},
      {"Stripe Key", std::regex(R"(sk_live_[0-9a-zA-Z]{24,})"), "critical"},
      {"Database URL", std::regex(R"((?:mysql|postgres|mongodb)://[^\s"'<]+:[^\s"'<]+@[^\s"'<]+)"), "critical"},
      {"Password in Config", std::regex(R"((?:password|passwd|pwd|secret)\s*[:=]\s*["'][^"']{4,}["'])"), "high"},
  };

  // Scan crawled URLs + common config endpoints
  std::vector<std::string> urls_to_check = crawl.urls;
  if (!crawl.urls.empty()) {
    std::string base = base_url_from(crawl.urls[0]);
    for (const auto& p : {"/api/config", "/env", "/debug", "/status", "/actuator/env", "/.env"}) {
      urls_to_check.push_back(base + p);
    }
  }

  size_t limit = std::min(urls_to_check.size(), size_t(50));
  for (size_t i = 0; i < limit; ++i) {
    auto resp = http.get(urls_to_check[i]);
    if (resp.status_code != 200 || resp.body.empty()) continue;

    for (const auto& pat : patterns) {
      std::smatch m;
      if (std::regex_search(resp.body, m, pat.re)) {
        std::string evidence = m[0].str();
        // Mask the actual secret value
        if (evidence.size() > 20) evidence = evidence.substr(0, 10) + "..." + evidence.substr(evidence.size() - 5);
        findings.push_back({"Secrets Exposure", pat.severity, urls_to_check[i], pat.name + " found in response", "", "", evidence});
        break;  // one finding per URL
      }
    }
  }
  return findings;
}

/// Percent-encode probe values so libcurl and the target receive exact syntax.
std::string encode_probe(const std::string& value) {
  static constexpr char hex[] = "0123456789ABCDEF";
  std::string encoded;
  for (const unsigned char c : value) {
    if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      encoded += static_cast<char>(c);
    } else {
      encoded += '%';
      encoded += hex[c >> 4];
      encoded += hex[c & 0x0f];
    }
  }
  return encoded;
}

/// Counterfactual Template Consensus (CTC): two independently generated math
/// canaries must evaluate while a syntax-matched invalid expression must not.
/// Unlike reflection or single-number checks, all three proof obligations must
/// agree before Apex reports a vulnerability.
std::vector<Finding> scan_counterfactual_template_consensus(
    const Config& cfg, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  struct Syntax {
    const char* name;
    const char* open;
    const char* close;
  };
  const std::vector<Syntax> syntaxes = {
      {"Jinja/Twig", "{{", "}}"}, {"Expression Language", "${", "}"},
      {"Unified EL", "#{", "}"}, {"ERB/EJS", "<%=", "%>"}};

  std::set<std::string> tested;
  const size_t max_params = cfg.deep ? 12 : 6;
  size_t tested_params = 0;

  for (const auto& parameter : crawl.params) {
    if (tested_params >= max_params) break;
    if (parameter.method == "POST" || parameter.type == "body") continue;
    const std::string key = parameter.url + "|" + parameter.name;
    if (!tested.insert(key).second) continue;
    ++tested_params;

    const size_t seed = std::hash<std::string>{}(key);
    const long long a = 137 + static_cast<long long>(seed % 41);
    const long long b = 239 + static_cast<long long>((seed >> 8) % 43);
    const long long c = 181 + static_cast<long long>((seed >> 16) % 47);
    const long long d = 283 + static_cast<long long>((seed >> 24) % 53);
    const std::string expected_a = std::to_string(a * b);
    const std::string expected_b = std::to_string(c * d);
    const std::string target = parameter.url + "?" + parameter.name + "=";
    const auto baseline = http.get(target + encode_probe("apex_ctc_" + std::to_string(seed)));
    if (baseline.status_code < 200 || baseline.status_code >= 400) continue;

    for (const auto& syntax : syntaxes) {
      const std::string expression_a = std::string(syntax.open) + std::to_string(a) + "*" + std::to_string(b) + syntax.close;
      const std::string expression_b = std::string(syntax.open) + std::to_string(c) + "*" + std::to_string(d) + syntax.close;
      const std::string negative = std::string(syntax.open) + std::to_string(a) + "x" + std::to_string(b) + syntax.close;

      const auto positive_a = http.get(target + encode_probe(expression_a));
      const auto positive_b = http.get(target + encode_probe(expression_b));
      const auto negative_control = http.get(target + encode_probe(negative));
      if (!confirms_counterfactual_template_consensus(
              baseline, positive_a, positive_b, negative_control,
              expected_a, expected_b)) {
        continue;
      }

      Finding finding{
          "SSTI — Counterfactual Consensus", "critical", parameter.url,
          std::string("Template evaluation confirmed for ") + syntax.name +
              " using two independent arithmetic canaries and one syntax-matched negative control",
          parameter.name, expression_a,
          "canary_a=" + expected_a + "; canary_b=" + expected_b +
              "; negative_control=no evaluation"};
      finding.confidence = 98;
      finding.cwe_id = "CWE-1336";
      finding.owasp_category = "A03:2021 Injection";
      finding.cvss_score = 9.8;
      findings.push_back(std::move(finding));
      break;
    }
  }
  return findings;
}

}  // namespace

std::vector<Scanner> register_detection_gap_scanners() {
  return {
      {"SSTI Deep", scan_ssti_deep},
      {"NoSQL Injection", scan_nosql},
      {"IDOR", scan_idor},
      {"CORS Deep", scan_cors_deep},
      {"Secrets Exposure", scan_response_secrets},
      {"Counterfactual Template Consensus", scan_counterfactual_template_consensus},
  };
}

}  // namespace apex
