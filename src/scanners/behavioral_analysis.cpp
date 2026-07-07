/// @file scanners/behavioral_analysis.cpp
/// @brief Behavioral Analysis Engine: detects vulnerabilities by observing
///        response behavior patterns rather than matching signatures.
///        Finds what signature-based scanners CANNOT find.
///
///        Techniques:
///        - Response time differential analysis (blind injection)
///        - Content-length differential (boolean-based blind)
///        - Status code state machine analysis (auth bypass paths)
///        - Header differential fingerprinting (hidden functionality)
///        - Entropy analysis (weak randomness in tokens)
#include <chrono>
#include <cmath>
#include <numeric>
#include <regex>
#include <set>

#include "scanner_base.hpp"

namespace apex {
namespace {

/// Calculate Shannon entropy of a string (measures randomness).
double shannon_entropy(const std::string& s) {
  if (s.empty()) return 0.0;
  std::map<char, int> freq;
  for (char c : s) freq[c]++;
  double entropy = 0.0;
  double len = static_cast<double>(s.size());
  for (const auto& [ch, count] : freq) {
    double p = count / len;
    entropy -= p * std::log2(p);
  }
  return entropy;
}

/// Detect weak randomness in tokens/session IDs.
std::vector<Finding> scan_weak_randomness(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Collect multiple tokens from the same endpoint
  std::vector<std::string> tokens;
  auto resp = http.get(base);

  // Extract tokens from Set-Cookie
  for (const auto& [key, val] : resp.headers) {
    std::string lower = key;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower == "set-cookie") {
      std::regex token_re(R"x(=([A-Za-z0-9+/=_-]{16,}))x");
      std::smatch m;
      if (std::regex_search(val, m, token_re)) {
        tokens.push_back(m[1].str());
      }
    }
  }

  // Get more samples
  for (int i = 0; i < 4 && tokens.size() < 5; i++) {
    auto r = http.get(base);
    for (const auto& [key, val] : r.headers) {
      std::string lower = key;
      std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
      if (lower == "set-cookie") {
        std::regex token_re(R"x(=([A-Za-z0-9+/=_-]{16,}))x");
        std::smatch m;
        if (std::regex_search(val, m, token_re)) {
          tokens.push_back(m[1].str());
        }
      }
    }
  }

  if (tokens.size() >= 3) {
    // Check entropy
    double avg_entropy = 0;
    for (const auto& t : tokens) avg_entropy += shannon_entropy(t);
    avg_entropy /= tokens.size();

    if (avg_entropy < 3.5) {
      findings.push_back(Finding{"Weak Token Randomness", "high", base,
                                 "Session tokens have low entropy (" + std::to_string(avg_entropy).substr(0, 4) +
                                     " bits/char, expected >4.5). Tokens may be predictable/brute-forceable. "
                                     "Sample: " +
                                     tokens[0].substr(0, 30) + "...",
                                 "", "", ""});
    }

    // Check for sequential/similar tokens
    if (tokens.size() >= 2) {
      int common_prefix = 0;
      for (size_t i = 0; i < std::min(tokens[0].size(), tokens[1].size()); i++) {
        if (tokens[0][i] == tokens[1][i])
          common_prefix++;
        else
          break;
      }
      if (common_prefix > tokens[0].size() / 2) {
        findings.push_back(Finding{"Sequential Token Pattern", "high", base,
                                   "Tokens share " + std::to_string(common_prefix) + "/" + std::to_string(tokens[0].size()) +
                                       " character prefix. "
                                       "Likely timestamp-based or counter-based — predictable.",
                                   "", tokens[0].substr(0, 40), tokens[1].substr(0, 40)});
      }
    }
  }

  return findings;
}

/// Boolean-based blind detection via content-length differentials.
std::vector<Finding> scan_blind_boolean(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  for (const auto& url : crawl.urls) {
    auto qpos = url.find('?');
    if (qpos == std::string::npos) continue;

    std::regex num_re(R"x(([^&=]+)=(\d+))x");
    std::string query = url.substr(qpos + 1);
    std::sregex_iterator it(query.begin(), query.end(), num_re);
    std::sregex_iterator end;

    for (; it != end; ++it) {
      std::string param = (*it)[1].str();
      std::string val = (*it)[2].str();
      std::string inject_url = url.substr(0, qpos + 1) + param + "=" + val;

      // True condition: AND 1=1
      auto true_resp = http.get(inject_url + "' AND '1'='1");
      // False condition: AND 1=2
      auto false_resp = http.get(inject_url + "' AND '1'='2");
      // Baseline
      auto base_resp = http.get(inject_url);

      // If true_resp matches baseline but false_resp differs = boolean blind SQLi
      if (true_resp.status_code == 200 && false_resp.status_code == 200 && base_resp.status_code == 200) {
        int true_diff = std::abs((int)true_resp.body.size() - (int)base_resp.body.size());
        int false_diff = std::abs((int)false_resp.body.size() - (int)base_resp.body.size());

        if (true_diff < 50 && false_diff > 100) {
          findings.push_back(Finding{"Blind SQLi — Boolean-Based (Behavioral)", "critical", inject_url,
                                     "Behavioral analysis detected boolean-based blind SQL injection. "
                                     "True condition (AND 1=1): response matches baseline (" +
                                         std::to_string(true_resp.body.size()) +
                                         " bytes). "
                                         "False condition (AND 1=2): response differs (" +
                                         std::to_string(false_resp.body.size()) +
                                         " bytes). "
                                         "This confirms injection without error messages.",
                                     param, "' AND '1'='1 vs ' AND '1'='2", "Delta: " + std::to_string(false_diff) + " bytes"});
          return findings;
        }
      }
      return findings;
    }
    break;
  }
  return findings;
}

/// Time-based behavioral analysis — detect blind vulns via response time.
std::vector<Finding> scan_blind_timing(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  for (const auto& url : crawl.urls) {
    auto qpos = url.find('?');
    if (qpos == std::string::npos) continue;

    std::regex param_re(R"x(([^&=]+)=([^&]+))x");
    std::string query = url.substr(qpos + 1);
    std::sregex_iterator it(query.begin(), query.end(), param_re);
    std::sregex_iterator end;

    for (; it != end; ++it) {
      std::string param = (*it)[1].str();
      std::string val = (*it)[2].str();
      std::string inject_url = url.substr(0, qpos + 1) + param + "=";

      // Baseline timing (3 samples)
      std::vector<long> baselines;
      for (int i = 0; i < 3; i++) {
        auto start = std::chrono::steady_clock::now();
        http.get(inject_url + val);
        baselines.push_back(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count());
      }
      long avg_baseline = std::accumulate(baselines.begin(), baselines.end(), 0L) / 3;

      // Time-based SQLi payloads
      std::vector<std::pair<std::string, std::string>> time_payloads = {
          {val + "' AND SLEEP(3)--", "MySQL SLEEP"},
          {val + "'; WAITFOR DELAY '0:0:3'--", "MSSQL WAITFOR"},
          {val + "' AND pg_sleep(3)--", "PostgreSQL pg_sleep"},
          {val + "' OR SLEEP(3)#", "MySQL OR SLEEP"},
      };

      for (const auto& [payload, db_type] : time_payloads) {
        auto start = std::chrono::steady_clock::now();
        http.get(inject_url + payload);
        long elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();

        if (elapsed > avg_baseline + 2500) {
          findings.push_back(Finding{"Blind SQLi — Time-Based (" + db_type + ")", "critical", inject_url + payload,
                                     "Behavioral timing analysis confirms blind SQL injection. "
                                     "Baseline: " +
                                         std::to_string(avg_baseline) +
                                         "ms. "
                                         "With SLEEP payload: " +
                                         std::to_string(elapsed) +
                                         "ms. "
                                         "Delta: " +
                                         std::to_string(elapsed - avg_baseline) +
                                         "ms. "
                                         "Database type: " +
                                         db_type,
                                     param, payload, ""});
          return findings;
        }
      }
      return findings;
    }
    break;
  }
  return findings;
}

/// Status code state machine — find auth bypass by mapping valid/invalid paths.
std::vector<Finding> scan_auth_state_machine(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Protected endpoints that should return 401/403
  std::vector<std::string> protected_paths = {"/admin",  "/dashboard", "/api/admin", "/internal",
                                              "/manage", "/settings",  "/api/users", "/panel"};

  for (const auto& path : protected_paths) {
    auto normal = http.get(base + path);
    if (normal.status_code != 401 && normal.status_code != 403) continue;

    // Try bypass techniques
    struct Bypass {
      std::string technique;
      std::string url;
      std::vector<std::pair<std::string, std::string>> headers;
    };

    std::vector<Bypass> bypasses = {
        {"Path traversal", base + "/./admin/../admin", {}},
        {"Double URL encode", base + "/%2561dmin", {}},
        {"Case variation", base + "/Admin", {}},
        {"Trailing dot", base + "/admin.", {}},
        {"Trailing slash", base + "/admin/", {}},
        {"Semicolon", base + "/admin;", {}},
        {"Null byte", base + "/admin%00", {}},
        {"X-Original-URL", base + "/", {{"X-Original-URL", path}}},
        {"X-Rewrite-URL", base + "/", {{"X-Rewrite-URL", path}}},
        {"X-Custom-IP-Auth", base + path, {{"X-Forwarded-For", "127.0.0.1"}}},
        {"X-Real-IP local", base + path, {{"X-Real-IP", "127.0.0.1"}}},
        {"Method override GET→POST", base + path, {{"X-HTTP-Method-Override", "POST"}}},
    };

    for (const auto& bp : bypasses) {
      auto resp = http.get(bp.url, bp.headers);
      if (resp.status_code == 200 && resp.body.size() > 100 && resp.body != normal.body &&
          resp.body.find("unauthorized") == std::string::npos && resp.body.find("forbidden") == std::string::npos &&
          resp.body.find("login") == std::string::npos) {
        findings.push_back(Finding{"Auth Bypass — " + bp.technique, "critical", bp.url,
                                   "Protected endpoint " + path + " (normally " + std::to_string(normal.status_code) +
                                       ") is accessible via: " + bp.technique + ". Returned " + std::to_string(resp.status_code) +
                                       " with " + std::to_string(resp.body.size()) + " bytes of content.",
                                   "", bp.technique, resp.body.substr(0, 200)});
        return findings;  // Critical — one is enough
      }
    }
  }
  return findings;
}

/// Hidden parameter discovery via behavioral response changes.
std::vector<Finding> scan_hidden_params(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Common hidden/debug parameters
  std::vector<std::string> hidden_params = {
      "debug",      "test",          "admin",          "internal",     "verbose",     "trace",           "dev",      "staging",
      "raw",        "source",        "dump",           "export",       "format=json", "format=xml",      "callback", "jsonp",
      "role=admin", "is_admin=true", "access_level=9", "preview=true", "draft=true",  "unpublished=true"};

  auto baseline = http.get(base);

  for (const auto& param : hidden_params) {
    std::string sep = (base.find('?') != std::string::npos) ? "&" : "?";
    auto resp = http.get(base + sep + param + "=true");

    if (resp.status_code == 200 && resp.body != baseline.body) {
      int size_diff = std::abs((int)resp.body.size() - (int)baseline.body.size());
      if (size_diff > 100) {
        findings.push_back(Finding{"Hidden Parameter — " + param, "medium", base + sep + param + "=true",
                                   "Adding '" + param + "' parameter changes response by " + std::to_string(size_diff) +
                                       " bytes. "
                                       "May unlock debug info, admin features, or bypass access controls.",
                                   param, "true", "Size delta: " + std::to_string(size_diff) + " bytes"});
      }
    }
  }
  return findings;
}

}  // namespace

std::vector<Scanner> register_behavioral_analysis_scanners() {
  return {
      {"Weak Randomness", scan_weak_randomness},       {"Blind Boolean", scan_blind_boolean},     {"Blind Timing", scan_blind_timing},
      {"Auth State Machine", scan_auth_state_machine}, {"Hidden Parameters", scan_hidden_params},
  };
}

}  // namespace apex
