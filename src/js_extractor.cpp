/// @file js_extractor.cpp
/// @brief JavaScript secret extractor: scans JS files for hardcoded secrets.
#include "js_extractor.hpp"

#include <algorithm>
#include <regex>
#include <set>
#include <sstream>

namespace apex {

const std::vector<JSExtractor::SecretPattern> JSExtractor::patterns_ = {
    // AWS
    {"AWS Access Key", R"(AKIA[0-9A-Z]{16})", "critical", "CWE-798"},
    {"AWS Secret Key",
     R"((?:aws_secret_access_key|secret_key)[\s]*[=:][\s]*['\"]([A-Za-z0-9/+=]{40})['\"])",
     "critical", "CWE-798"},

    // Google
    {"Google API Key", R"(AIza[0-9A-Za-z\-_]{35})", "high", "CWE-798"},
    {"Google OAuth",
     R"(\d{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com)", "high",
     "CWE-798"},

    // Firebase
    {"Firebase Config",
     R"(firebase[a-z]*[\s]*[=:][\s]*['\"]([A-Za-z0-9_\-]+\.firebaseio\.com)['\"])",
     "high", "CWE-798"},
    {"Firebase API Key",
     R"((?:apiKey|firebase_api_key)[\s]*[=:]\s*['\"]([A-Za-z0-9_\-]{39})['\"])",
     "high", "CWE-798"},

    // Stripe
    {"Stripe Secret Key", R"(sk_live_[0-9a-zA-Z]{24,})", "critical",
     "CWE-798"},
    {"Stripe Publishable Key", R"(pk_live_[0-9a-zA-Z]{24,})", "medium",
     "CWE-798"},

    // GitHub
    {"GitHub Token", R"(gh[pousr]_[A-Za-z0-9_]{36,})", "critical", "CWE-798"},
    {"GitHub OAuth",
     R"(github[_\-]?(?:token|secret|key)[\s]*[=:][\s]*['\"]([a-f0-9]{40})['\"])",
     "critical", "CWE-798"},

    // Generic secrets
    {"Generic API Key",
     R"((?:api[_\-]?key|apikey|api_secret)[\s]*[=:][\s]*['\"]([A-Za-z0-9_\-]{16,64})['\"])",
     "high", "CWE-798"},
    {"Generic Secret",
     R"((?:secret|token|password|passwd|pwd|credential)[\s]*[=:][\s]*['\"]([^\s'"]{8,})['\"])",
     "high", "CWE-798"},
    {"Bearer Token",
     R"((?:bearer|authorization)[\s]*[=:][\s]*['\"](?:Bearer\s+)?([A-Za-z0-9_\-\.]{20,})['\"])",
     "high", "CWE-798"},

    // Private keys
    {"Private Key", R"(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)", "critical",
     "CWE-321"},

    // Slack
    {"Slack Token", R"(xox[baprs]-[0-9a-zA-Z\-]{10,})", "high", "CWE-798"},
    {"Slack Webhook",
     R"(https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+)",
     "medium", "CWE-798"},

    // Twilio
    {"Twilio API Key", R"(SK[0-9a-fA-F]{32})", "high", "CWE-798"},

    // Mailgun
    {"Mailgun API Key", R"(key-[0-9a-zA-Z]{32})", "high", "CWE-798"},

    // SendGrid
    {"SendGrid API Key", R"(SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43})",
     "high", "CWE-798"},

    // Heroku
    {"Heroku API Key",
     R"([hH]eroku[a-zA-Z_]*[=:][\s]*['\"]([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"])",
     "high", "CWE-798"},

    // Internal URLs and endpoints
    {"Internal URL",
     R"((https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)[:\d]*/[^\s'"<>]+))",
     "medium", "CWE-200"},
    {"Internal API Endpoint",
     R"((?:internal|staging|dev|test|local)[_\-]?(?:api|url|endpoint|host)[\s]*[=:][\s]*['\"]([^'"]+)['\"])",
     "medium", "CWE-200"},

    // Admin paths
    {"Admin Path",
     R"([\s=:]['\"](/(?:admin|_admin|administrator|wp-admin|phpmyadmin|panel|manage|internal)[/\w]*)['\"])",
     "low", "CWE-200"},

    // Hardcoded credentials
    {"Hardcoded Password",
     R"((?:password|passwd|pwd)[\s]*[=:][\s]*['\"]([^'\"]{4,})['\"])",
     "high", "CWE-798"},
    {"Hardcoded Username",
     R"((?:username|user|login|email)[\s]*[=:][\s]*['\"]([^'\"]+@[^'\"]+|admin|root|test)['\"])",
     "low", "CWE-798"},

    // Source maps
    {"Source Map",
     R"(//[#@]\s*sourceMappingURL\s*=\s*([^\s]+\.map))", "low", "CWE-200"},
    {"Source Map URL",
     R"([\s=:]['\"]([^\s'"]+\.map)['\"])", "low", "CWE-200"},

    // JWT tokens (static/hardcoded)
    {"JWT Token",
     R"(eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)",
     "high", "CWE-798"},
};

JSExtractor::JSExtractor(HttpClient &http, const Config &cfg)
    : http_(http), cfg_(cfg) {}

std::vector<Finding> JSExtractor::extract(const CrawlResult &crawl) {
  std::vector<Finding> findings;
  std::set<std::string> scanned_urls;
  std::set<std::string> seen_secrets; // Deduplicate

  // Find all JS URLs
  auto js_urls = find_js_urls(crawl);

  // Process each JS file
  for (const auto &js_url : js_urls) {
    if (scanned_urls.count(js_url)) continue;
    scanned_urls.insert(js_url);

    auto resp = http_.get(js_url);
    if (resp.status_code != 200 || resp.body.empty()) continue;

    // Scan for secrets
    auto js_findings = scan_js_content(js_url, resp.body);
    for (auto &f : js_findings) {
      // Deduplicate based on type + evidence
      std::string key = f.type + "|" + f.evidence;
      if (seen_secrets.count(key)) continue;
      seen_secrets.insert(key);
      findings.push_back(f);
    }

    // Find webpack chunks for additional JS files
    auto chunks = find_webpack_chunks(resp.body, js_url);
    for (const auto &chunk_url : chunks) {
      if (scanned_urls.count(chunk_url)) continue;
      scanned_urls.insert(chunk_url);

      auto chunk_resp = http_.get(chunk_url);
      if (chunk_resp.status_code != 200 || chunk_resp.body.empty()) continue;

      auto chunk_findings = scan_js_content(chunk_url, chunk_resp.body);
      for (auto &f : chunk_findings) {
        std::string key = f.type + "|" + f.evidence;
        if (seen_secrets.count(key)) continue;
        seen_secrets.insert(key);
        findings.push_back(f);
      }
    }
  }

  return findings;
}

std::vector<std::string> JSExtractor::find_js_urls(const CrawlResult &crawl) {
  std::vector<std::string> js_urls;
  std::set<std::string> seen;

  // From crawled URLs
  for (const auto &url : crawl.urls) {
    if (url.size() > 3) {
      std::string lower = url;
      std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
      if (lower.find(".js") != std::string::npos &&
          lower.find(".json") == std::string::npos) {
        if (!seen.count(url)) {
          seen.insert(url);
          js_urls.push_back(url);
        }
      }
    }
  }

  // Extract from HTML pages — look for script src attributes
  static const std::regex script_src(R"(<script[^>]+src=["']([^"']+\.js[^"']*?)["'])");
  for (const auto &url : crawl.urls) {
    // Only fetch HTML pages
    std::string lower = url;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower.find(".js") != std::string::npos ||
        lower.find(".css") != std::string::npos ||
        lower.find(".png") != std::string::npos ||
        lower.find(".jpg") != std::string::npos)
      continue;

    auto resp = http_.get(url);
    if (resp.status_code != 200) continue;

    std::sregex_iterator it(resp.body.begin(), resp.body.end(), script_src);
    std::sregex_iterator end;
    for (; it != end; ++it) {
      std::string src = (*it)[1].str();
      std::string resolved = resolve_url(url, src);
      if (!seen.count(resolved)) {
        seen.insert(resolved);
        js_urls.push_back(resolved);
      }
    }

    // Limit HTML pages to check (avoid excessive crawling)
    if (js_urls.size() > 100) break;
  }

  return js_urls;
}

std::vector<std::string>
JSExtractor::find_webpack_chunks(const std::string &js_content,
                                 const std::string &base_url) {
  std::vector<std::string> chunks;

  // Webpack chunk manifest patterns
  static const std::regex chunk_pattern1(
      R"(["']([a-zA-Z0-9_\-]+\.chunk\.js)["'])");
  static const std::regex chunk_pattern2(
      R"(["']([a-zA-Z0-9_\-]+\.[a-f0-9]{8}\.js)["'])");
  static const std::regex chunk_pattern3(
      R"((?:__webpack_require__|webpackJsonp)[^;]*["']([^"']+\.js)["'])");

  std::string base = base_url;
  auto last_slash = base.rfind('/');
  if (last_slash != std::string::npos) {
    base = base.substr(0, last_slash + 1);
  }

  auto extract_chunks = [&](const std::regex &pattern) {
    std::sregex_iterator it(js_content.begin(), js_content.end(), pattern);
    std::sregex_iterator end;
    for (; it != end && chunks.size() < 50; ++it) {
      std::string chunk = (*it)[1].str();
      std::string chunk_url = resolve_url(base, chunk);
      chunks.push_back(chunk_url);
    }
  };

  extract_chunks(chunk_pattern1);
  extract_chunks(chunk_pattern2);
  extract_chunks(chunk_pattern3);

  return chunks;
}

std::vector<Finding> JSExtractor::scan_js_content(const std::string &url,
                                                  const std::string &content) {
  std::vector<Finding> findings;

  for (const auto &pattern : patterns_) {
    try {
      std::regex re(pattern.regex, std::regex::icase);
      std::sregex_iterator it(content.begin(), content.end(), re);
      std::sregex_iterator end;

      int matches_per_pattern = 0;
      for (; it != end && matches_per_pattern < 5; ++it) {
        ++matches_per_pattern;
        std::string matched = (*it)[0].str();

        // Skip obvious false positives
        if (matched.size() < 5) continue;
        if (matched.find("example") != std::string::npos) continue;
        if (matched.find("placeholder") != std::string::npos) continue;
        if (matched.find("your-") != std::string::npos) continue;
        if (matched.find("xxx") != std::string::npos) continue;
        if (matched.find("TODO") != std::string::npos) continue;

        // Get surrounding context
        auto pos = static_cast<size_t>((*it).position());
        size_t ctx_start = (pos > 40) ? pos - 40 : 0;
        size_t ctx_end = std::min(pos + matched.size() + 40, content.size());
        std::string context = content.substr(ctx_start, ctx_end - ctx_start);
        // Clean up context (remove newlines)
        std::replace(context.begin(), context.end(), '\n', ' ');
        std::replace(context.begin(), context.end(), '\r', ' ');

        Finding f;
        f.type = "JS Secret: " + pattern.name;
        f.severity = pattern.severity;
        f.url = url;
        f.detail = pattern.name + " found in JavaScript file";
        f.evidence = context.substr(0, 200);
        f.confidence = 75;
        f.cwe_id = pattern.cwe;
        f.owasp_category = "A02:2021 Cryptographic Failures";
        f.cvss_score = (pattern.severity == "critical")  ? 9.0
                       : (pattern.severity == "high")    ? 7.5
                       : (pattern.severity == "medium")  ? 5.0
                                                         : 3.0;
        findings.push_back(f);
      }
    } catch (const std::regex_error &) {
      // Skip invalid regex patterns
      continue;
    }
  }

  return findings;
}

std::string JSExtractor::resolve_url(const std::string &base,
                                     const std::string &relative) {
  if (relative.find("http://") == 0 || relative.find("https://") == 0) {
    return relative;
  }
  if (relative.find("//") == 0) {
    // Protocol-relative
    auto colon = base.find(':');
    if (colon != std::string::npos) {
      return base.substr(0, colon + 1) + relative;
    }
    return "https:" + relative;
  }
  if (relative.find('/') == 0) {
    // Absolute path
    static const std::regex origin_re(R"((https?://[^/]+))");
    std::smatch m;
    if (std::regex_search(base, m, origin_re)) {
      return m[1].str() + relative;
    }
  }
  // Relative path
  auto last_slash = base.rfind('/');
  if (last_slash != std::string::npos) {
    return base.substr(0, last_slash + 1) + relative;
  }
  return base + "/" + relative;
}

} // namespace apex
