#include "security_scanner.hpp"

#include <chrono>
#include <fstream>
#include <nlohmann/json.hpp>
#include <regex>

using json = nlohmann::json;

namespace apex {

SecurityScanner::SecurityScanner(const std::string& target_url) : target_url_(target_url), http_client_(std::make_unique<HttpClient>()) {}

void SecurityScanner::enable_spa_mode(bool enable) { spa_mode_ = enable; }

void SecurityScanner::set_auth_jwt(const std::string& token) { auth_headers_["Authorization"] = "Bearer " + token; }

void SecurityScanner::set_auth_cookie(const std::string& name, const std::string& value) { auth_headers_["Cookie"] = name + "=" + value; }

std::vector<SecurityFinding> SecurityScanner::scan_full() {
  findings_.clear();

  // OWASP Top 10 2021 checks
  auto injection = check_injection();
  findings_.insert(findings_.end(), injection.begin(), injection.end());

  auto xss = check_xss();
  findings_.insert(findings_.end(), xss.begin(), xss.end());

  auto auth = check_auth();
  findings_.insert(findings_.end(), auth.begin(), auth.end());

  auto access = check_access_control();
  findings_.insert(findings_.end(), access.begin(), access.end());

  auto misconfig = check_security_misconfig();
  findings_.insert(findings_.end(), misconfig.begin(), misconfig.end());

  auto ssrf = check_ssrf();
  findings_.insert(findings_.end(), ssrf.begin(), ssrf.end());

  // Next.js specific
  if (spa_mode_) {
    auto nextjs_env = check_nextjs_env_exposure();
    findings_.insert(findings_.end(), nextjs_env.begin(), nextjs_env.end());

    auto nextjs_api = check_nextjs_api_routes();
    findings_.insert(findings_.end(), nextjs_api.begin(), nextjs_api.end());
  }

  // GraphQL
  for (const auto& endpoint : graphql_endpoints_) {
    auto graphql = check_graphql_introspection();
    findings_.insert(findings_.end(), graphql.begin(), graphql.end());
  }

  return findings_;
}

std::vector<SecurityFinding> SecurityScanner::check_injection() {
  std::vector<SecurityFinding> results;

  // SQL injection payloads
  std::vector<std::string> sqli_payloads = {"' OR '1'='1", "' OR '1'='1' --",        "' OR '1'='1' /*",
                                            "admin'--",    "1' UNION SELECT NULL--", "' AND 1=CONVERT(int, (SELECT @@version))--"};

  // Test common parameters
  std::vector<std::string> params = {"id", "user", "search", "q", "filter"};

  for (const auto& param : params) {
    for (const auto& payload : sqli_payloads) {
      std::string test_url = target_url_ + "?" + param + "=" + payload;

      auto response = http_client_->get(test_url, auth_headers_);

      // Check for SQL error messages
      std::vector<std::string> error_patterns = {"SQL syntax",        "mysql_fetch",    "ORA-[0-9]+",
                                                 "PostgreSQL.*ERROR", "Warning.*mysql", "SQLite.*error"};

      for (const auto& pattern : error_patterns) {
        if (std::regex_search(response.body, std::regex(pattern, std::regex::icase))) {
          SecurityFinding finding;
          finding.id = "sqli-" + param;
          finding.name = "SQL Injection";
          finding.description = "SQL injection vulnerability detected in parameter: " + param;
          finding.severity = SeverityLevel::CRITICAL;
          finding.url = test_url;
          finding.evidence = "Payload: " + payload;
          finding.cwe = "CWE-89";
          finding.owasp_category = "A03:2021-Injection";
          results.push_back(finding);
          break;
        }
      }
    }
  }

  return results;
}

std::vector<SecurityFinding> SecurityScanner::check_xss() {
  std::vector<SecurityFinding> results;

  std::vector<std::string> xss_payloads = {"<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "javascript:alert('XSS')",
                                           "<svg onload=alert('XSS')>", "'\"><script>alert(String.fromCharCode(88,83,83))</script>"};

  std::vector<std::string> params = {"q", "search", "name", "comment", "message"};

  for (const auto& param : params) {
    for (const auto& payload : xss_payloads) {
      std::string test_url = target_url_ + "?" + param + "=" + payload;
      auto response = http_client_->get(test_url, auth_headers_);

      if (response.body.find(payload) != std::string::npos) {
        SecurityFinding finding;
        finding.id = "xss-" + param;
        finding.name = "Cross-Site Scripting (XSS)";
        finding.description = "Reflected XSS vulnerability in parameter: " + param;
        finding.severity = SeverityLevel::HIGH;
        finding.url = test_url;
        finding.evidence = "Payload reflected: " + payload;
        finding.cwe = "CWE-79";
        finding.owasp_category = "A03:2021-Injection";
        results.push_back(finding);
        break;
      }
    }
  }

  return results;
}

std::vector<SecurityFinding> SecurityScanner::check_security_misconfig() {
  std::vector<SecurityFinding> results;

  auto response = http_client_->get(target_url_, auth_headers_);

  // Check security headers
  std::map<std::string, std::string> required_headers = {{"X-Content-Type-Options", "nosniff"},
                                                         {"X-Frame-Options", "DENY"},
                                                         {"Strict-Transport-Security", "max-age="},
                                                         {"Content-Security-Policy", "default-src"}};

  for (const auto& [header, expected] : required_headers) {
    auto it = response.headers.find(header);
    if (it == response.headers.end() || it->second.find(expected) == std::string::npos) {
      SecurityFinding finding;
      finding.id = "missing-header-" + header;
      finding.name = "Missing Security Header";
      finding.description = "Missing or misconfigured security header: " + header;
      finding.severity = SeverityLevel::MEDIUM;
      finding.url = target_url_;
      finding.evidence = "Header not found or incorrect value";
      finding.cwe = "CWE-16";
      finding.owasp_category = "A05:2021-Security Misconfiguration";
      results.push_back(finding);
    }
  }

  return results;
}

std::vector<SecurityFinding> SecurityScanner::check_nextjs_env_exposure() {
  std::vector<SecurityFinding> results;

  std::vector<std::string> env_files = {"/.env", "/.env.local", "/.env.production", "/.env.development", "/.env.test"};

  for (const auto& file : env_files) {
    auto response = http_client_->get(target_url_ + file, auth_headers_);

    if (response.status_code == 200) {
      std::vector<std::string> sensitive_patterns = {"DATABASE_URL", "API_KEY", "SECRET", "PASSWORD", "PRIVATE_KEY"};

      for (const auto& pattern : sensitive_patterns) {
        if (response.body.find(pattern) != std::string::npos) {
          SecurityFinding finding;
          finding.id = "nextjs-env-exposure";
          finding.name = "Next.js Environment Variables Exposed";
          finding.description = "Sensitive environment file accessible: " + file;
          finding.severity = SeverityLevel::CRITICAL;
          finding.url = target_url_ + file;
          finding.evidence = "Found sensitive pattern: " + pattern;
          finding.cwe = "CWE-200";
          finding.owasp_category = "A01:2021-Broken Access Control";
          results.push_back(finding);
          break;
        }
      }
    }
  }

  return results;
}

std::vector<SecurityFinding> SecurityScanner::check_nextjs_api_routes() {
  std::vector<SecurityFinding> results;

  std::vector<std::string> api_routes = {"/api/users", "/api/admin", "/api/config", "/api/debug", "/api/health"};

  for (const auto& route : api_routes) {
    auto response = http_client_->get(target_url_ + route, {});  // No auth

    if (response.status_code == 200 && response.body.find("unauthorized") == std::string::npos &&
        response.body.find("forbidden") == std::string::npos) {
      SecurityFinding finding;
      finding.id = "nextjs-api-noauth-" + route;
      finding.name = "Next.js API Route Without Authentication";
      finding.description = "API route accessible without authentication: " + route;
      finding.severity = SeverityLevel::HIGH;
      finding.url = target_url_ + route;
      finding.evidence = "HTTP " + std::to_string(response.status_code) + " without auth";
      finding.cwe = "CWE-306";
      finding.owasp_category = "A07:2021-Identification and Authentication Failures";
      results.push_back(finding);
    }
  }

  return results;
}

std::vector<SecurityFinding> SecurityScanner::check_graphql_introspection() {
  std::vector<SecurityFinding> results;

  for (const auto& endpoint : graphql_endpoints_) {
    std::string query = R"({"query":"{ __schema { types { name } } }"})";

    std::map<std::string, std::string> headers = auth_headers_;
    headers["Content-Type"] = "application/json";

    auto response = http_client_->post(endpoint, query, headers);

    if (response.status_code == 200 && response.body.find("__schema") != std::string::npos) {
      SecurityFinding finding;
      finding.id = "graphql-introspection";
      finding.name = "GraphQL Introspection Enabled";
      finding.description = "GraphQL introspection is enabled in production";
      finding.severity = SeverityLevel::MEDIUM;
      finding.url = endpoint;
      finding.evidence = "Introspection query successful";
      finding.cwe = "CWE-200";
      finding.owasp_category = "A05:2021-Security Misconfiguration";
      results.push_back(finding);
    }
  }

  return results;
}

std::vector<SecurityFinding> SecurityScanner::check_ssrf() {
  std::vector<SecurityFinding> results;

  std::vector<std::string> ssrf_payloads = {
      "http://169.254.169.254/latest/meta-data/",  // AWS metadata
      "http://metadata.google.internal/",          // GCP metadata
      "http://localhost:6379/",                    // Redis
      "http://127.0.0.1:8080/"                     // Internal services
  };

  std::vector<std::string> params = {"url", "link", "src", "redirect", "proxy"};

  for (const auto& param : params) {
    for (const auto& payload : ssrf_payloads) {
      std::string test_url = target_url_ + "?" + param + "=" + payload;
      auto response = http_client_->get(test_url, auth_headers_);

      if (response.status_code == 200 && response.body.size() > 0) {
        SecurityFinding finding;
        finding.id = "ssrf-" + param;
        finding.name = "Server-Side Request Forgery (SSRF)";
        finding.description = "SSRF vulnerability in parameter: " + param;
        finding.severity = SeverityLevel::CRITICAL;
        finding.url = test_url;
        finding.evidence = "Successfully fetched internal resource";
        finding.cwe = "CWE-918";
        finding.owasp_category = "A10:2021-Server-Side Request Forgery";
        results.push_back(finding);
        break;
      }
    }
  }

  return results;
}

void SecurityScanner::export_json(const std::string& path) const {
  json report;
  report["target"] = target_url_;
  report["scan_date"] = std::chrono::system_clock::now().time_since_epoch().count();
  report["total_findings"] = findings_.size();

  json findings_json = json::array();
  for (const auto& finding : findings_) {
    json f;
    f["id"] = finding.id;
    f["name"] = finding.name;
    f["description"] = finding.description;
    f["severity"] = static_cast<int>(finding.severity);
    f["url"] = finding.url;
    f["evidence"] = finding.evidence;
    f["cwe"] = finding.cwe;
    f["owasp"] = finding.owasp_category;
    findings_json.push_back(f);
  }
  report["findings"] = findings_json;

  std::ofstream file(path);
  file << report.dump(2);
}

void SecurityScanner::export_jsonl(const std::string& path) const {
  std::ofstream file(path, std::ios::app);

  for (const auto& finding : findings_) {
    json f;
    f["timestamp"] = std::chrono::system_clock::now().time_since_epoch().count();
    f["target"] = target_url_;
    f["id"] = finding.id;
    f["name"] = finding.name;
    f["severity"] = static_cast<int>(finding.severity);
    f["url"] = finding.url;
    f["cwe"] = finding.cwe;
    f["owasp"] = finding.owasp_category;

    file << f.dump() << "\n";
  }
}

std::map<std::string, int> SecurityScanner::get_owasp_coverage() const {
  std::map<std::string, int> coverage;

  for (const auto& finding : findings_) {
    coverage[finding.owasp_category]++;
  }

  return coverage;
}

std::vector<SecurityFinding> SecurityScanner::check_auth() { return {}; }
std::vector<SecurityFinding> SecurityScanner::check_access_control() { return {}; }
std::vector<SecurityFinding> SecurityScanner::check_sensitive_data() { return {}; }
std::vector<SecurityFinding> SecurityScanner::check_xxe() { return {}; }
std::vector<SecurityFinding> SecurityScanner::check_deserialization() { return {}; }
std::vector<SecurityFinding> SecurityScanner::check_components() { return {}; }
std::vector<SecurityFinding> SecurityScanner::check_logging() { return {}; }

}  // namespace apex
