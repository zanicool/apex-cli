/// @file scanners/waf.cpp
/// @brief WAF bypass: mutation techniques, JS secrets scanning, source map
///        discovery, dependency confusion detection.
#include "scanner_base.hpp"
#include <set>

namespace apex {
namespace {

/// WAF bypass via payload mutations.
std::vector<Finding> scan_waf_bypass(const Config &, HttpClient &http,
                                     const CrawlResult &crawl) {
  std::vector<Finding> findings;
  // Mutation functions.
  auto double_encode = [](const std::string &s) {
    std::string r;
    for (char c : s) {
      if (c == '<') r += "%253C";
      else if (c == '>') r += "%253E";
      else if (c == '\'') r += "%2527";
      else if (c == '"') r += "%2522";
      else r += c;
    }
    return r;
  };
  auto unicode_escape = [](const std::string &s) {
    std::string r;
    for (char c : s) {
      if (c == '<') r += "\\u003c";
      else if (c == '>') r += "\\u003e";
      else r += c;
    }
    return r;
  };
  auto comment_inject = [](const std::string &s) {
    std::string r;
    for (size_t i = 0; i < s.size(); ++i) {
      r += s[i];
      if (i % 3 == 2 && i + 1 < s.size()) r += "/**/";
    }
    return r;
  };

  const std::string base_payload = "<script>alert(1)</script>";
  struct Mutation {
    std::string name;
    std::string payload;
  };
  std::vector<Mutation> mutations = {
      {"Double Encode", double_encode(base_payload)},
      {"Unicode Escape", unicode_escape(base_payload)},
      {"Comment Inject", comment_inject("' OR 1=1--")},
      {"Case Randomize", "<ScRiPt>alert(1)</sCrIpT>"},
      {"Null Byte", "<scr%00ipt>alert(1)</script>"},
      {"Tab/Newline", "<scr\tipt>alert(1)</script>"},
  };

  for (const auto &url : crawl.urls) {
    auto targets = get_targets(crawl, url, "q");
    for (const auto &[base, param] : targets) {
      // First check if WAF blocks normal payload.
      auto blocked = http.get(base + base_payload);
      if (blocked.status_code != 403) continue; // No WAF, skip.

      for (const auto &mut : mutations) {
        auto resp = http.get(base + mut.payload);
        if (resp.status_code == 200) {
          findings.push_back({"WAF Bypass", "high", url,
                              "WAF bypassed via " + mut.name,
                              param, mut.payload, ""});
          break;
        }
      }
    }
  }
  return findings;
}

/// JS secrets scanner — find API keys, tokens in JavaScript files.
std::vector<Finding> scan_js_secrets(const Config &, HttpClient &http,
                                     const CrawlResult &crawl) {
  std::vector<Finding> findings;
  const std::vector<std::pair<std::regex, std::string>> patterns = {
      {std::regex(R"(AKIA[0-9A-Z]{16})"), "AWS Access Key"},
      {std::regex(R"re(api[_-]?key['":\s]*['"]([a-zA-Z0-9_\-]{20,})['"])re"), "API Key"},
      {std::regex(R"(-----BEGIN.*PRIVATE KEY-----)"), "Private Key"},
      {std::regex(R"(ghp_[a-zA-Z0-9]{36})"), "GitHub Token"},
      {std::regex(R"(sk-[a-zA-Z0-9]{32,})"), "OpenAI/Stripe Key"},
      {std::regex(R"(xox[baprs]-[a-zA-Z0-9-]+)"), "Slack Token"},
      {std::regex(R"(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+)"), "JWT Token"},
  };

  for (const auto &url : crawl.urls) {
    if (url.find(".js") == std::string::npos &&
        url.find("javascript") == std::string::npos)
      continue;
    auto resp = http.get(url);
    if (resp.status_code != 200) continue;
    for (const auto &[re, desc] : patterns) {
      if (std::regex_search(resp.body, re)) {
        findings.push_back({"JS Secret", "high", url,
                            "Potential " + desc + " in JS", "", "", ""});
      }
    }
  }
  return findings;
}

/// Source map discovery — find .map files that expose source code.
std::vector<Finding> scan_source_maps(const Config &, HttpClient &http,
                                      const CrawlResult &crawl) {
  std::vector<Finding> findings;
  for (const auto &url : crawl.urls) {
    if (url.find(".js") == std::string::npos) continue;

    // Check for sourceMappingURL in JS file.
    auto resp = http.get(url);
    if (resp.body.find("sourceMappingURL") != std::string::npos) {
      // Try fetching the .map file.
      std::string map_url = url + ".map";
      auto map_resp = http.get(map_url);
      if (map_resp.status_code == 200 &&
          map_resp.body.find("\"sources\"") != std::string::npos) {
        findings.push_back({"Source Map", "medium", map_url,
                            "JavaScript source map exposed", "", "", ""});
      }
    }
  }
  return findings;
}

/// Dependency confusion — check for internal package names.
std::vector<Finding> scan_dependency_confusion(const Config &, HttpClient &http,
                                               const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Check for package.json exposure.
  auto resp = http.get(base + "/package.json");
  if (resp.status_code != 200) return findings;

  // Look for scoped packages that might be internal.
  std::regex scope_re(R"re("@([a-z0-9-]+)/([a-z0-9-]+)")re");
  std::sregex_iterator it(resp.body.begin(), resp.body.end(), scope_re);
  std::sregex_iterator end;
  std::set<std::string> checked;

  for (; it != end; ++it) {
    std::string scope = (*it)[1].str();
    std::string pkg = (*it)[2].str();
    std::string full = "@" + scope + "/" + pkg;
    if (!checked.insert(full).second) continue;

    // Check if package exists on npm.
    auto npm = http.get("https://registry.npmjs.org/" + full);
    if (npm.status_code == 404) {
      findings.push_back({"Dependency Confusion", "high", base + "/package.json",
                          "Internal package not on npm: " + full,
                          "", full, ""});
    }
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_waf_scanners() {
  return {
      {"WAF Bypass", scan_waf_bypass},
      {"JS Secrets", scan_js_secrets},
      {"Source Maps", scan_source_maps},
      {"Dependency Confusion", scan_dependency_confusion},
  };
}

} // namespace apex
