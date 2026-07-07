/// @file scanners/recon_extra.cpp
/// @brief Extra recon scanners: subdomain takeover, SSL, broken links,
///        S3 perms, JS secrets, favicon hash, sitemap, security.txt
#include <regex>
#include <set>

#include "scanner_base.hpp"

namespace apex {
namespace {

// 1. Subdomain Takeover
std::vector<Finding> scan_subdomain_takeover(const Config& cfg, HttpClient& http, const CrawlResult& crawl) {
  (void)cfg;
  (void)crawl;
  std::vector<Finding> findings;
  std::vector<std::pair<std::string, std::string>> sigs = {
      {"NoSuchBucket", "AWS S3"},
      {"There isn't a GitHub Pages site here", "GitHub Pages"},
      {"Heroku | No such app", "Heroku"},
      {"<title>Fastly error: unknown domain", "Fastly"},
      {"The request could not be satisfied", "CloudFront"},
      {"Sorry, this shop is currently unavailable", "Shopify"},
      {"Do you want to register", "WordPress.com"},
      {"Project not found", "GitLab Pages"},
      {"Repository not found", "Bitbucket"},
  };
  // Check the target itself
  auto resp = http.get("https://" + cfg.target);
  for (auto& [sig, service] : sigs) {
    if (resp.body.find(sig) != std::string::npos) {
      findings.push_back({"Subdomain Takeover — " + service, "critical", "https://" + cfg.target, "", "", sig, "apex-takeover"});
    }
  }
  return findings;
}

// 2. SSL/TLS issues
std::vector<Finding> scan_ssl_issues(const Config& cfg, HttpClient& http, const CrawlResult& crawl) {
  (void)crawl;
  std::vector<Finding> findings;
  auto resp = http.get("https://" + cfg.target);
  // Check if HTTP works without redirect to HTTPS
  auto http_resp = http.get("http://" + cfg.target);
  if (http_resp.status_code == 200 && http_resp.body.size() > 100) {
    findings.push_back(
        {"No HTTPS Redirect", "medium", "http://" + cfg.target, "", "", "HTTP serves content without redirecting to HTTPS", ""});
  }
  return findings;
}

// 3. Broken link hijacking
std::vector<Finding> scan_broken_links(const Config& cfg, HttpClient& http, const CrawlResult& crawl) {
  (void)cfg;
  std::vector<Finding> findings;
  std::regex link_re(R"(https?://([a-zA-Z0-9.-]+))");
  std::set<std::string> checked;
  for (auto& url : crawl.urls) {
    auto resp = http.get(url);
    auto begin = std::sregex_iterator(resp.body.begin(), resp.body.end(), link_re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
      std::string domain = (*it)[1].str();
      if (domain.find(cfg.target) != std::string::npos) continue;
      if (!checked.insert(domain).second) continue;
      if (checked.size() > 20) break;
      auto ext = http.get("https://" + domain);
      if (ext.status_code == 0 || ext.body.find("This domain is for sale") != std::string::npos) {
        findings.push_back(
            {"Broken Link — Domain Available", "medium", url, "", "", "External link to " + domain + " — domain may be claimable", ""});
      }
    }
    if (checked.size() > 20) break;
  }
  return findings;
}

// 4. S3 bucket write test
std::vector<Finding> scan_s3_write(const Config& cfg, HttpClient& http, const CrawlResult& crawl) {
  (void)crawl;
  std::vector<Finding> findings;
  std::vector<std::string> buckets = {cfg.target, cfg.target + "-assets", cfg.target + "-uploads", cfg.target + "-backup"};
  // Only test listing, NOT writing (safe)
  for (auto& b : buckets) {
    std::string url = "https://" + b + ".s3.amazonaws.com";
    auto resp = http.get(url);
    if (resp.status_code == 200 && resp.body.find("ListBucketResult") != std::string::npos) {
      findings.push_back({"S3 Bucket Listable", "high", url, "", "", "Public listing enabled", ""});
    }
  }
  return findings;
}

// 5. JS secret scanner
std::vector<Finding> scan_js_secrets(const Config& cfg, HttpClient& http, const CrawlResult& crawl) {
  (void)cfg;
  std::vector<Finding> findings;
  std::vector<std::pair<std::string, std::string>> patterns = {
      {"AKIA[0-9A-Z]{16}", "AWS Access Key"},        {"sk_live_[0-9a-zA-Z]{24,}", "Stripe Secret Key"},
      {"ghp_[A-Za-z0-9_]{36,}", "GitHub Token"},     {"xox[baprs]-[0-9a-zA-Z-]{10,}", "Slack Token"},
      {"AIza[0-9A-Za-z\\-_]{35}", "Google API Key"}, {"-----BEGIN.*PRIVATE KEY", "Private Key"},
  };
  for (auto& url : crawl.urls) {
    if (url.find(".js") == std::string::npos) continue;
    auto resp = http.get(url);
    if (resp.body.size() < 100) continue;
    for (auto& [pat, name] : patterns) {
      std::regex re(pat);
      std::smatch m;
      if (std::regex_search(resp.body, m, re)) {
        findings.push_back({"JS Secret: " + name, "critical", url, "", "", m[0].str().substr(0, 20) + "...", ""});
        break;
      }
    }
  }
  return findings;
}

// 6. Favicon fingerprint
std::vector<Finding> scan_favicon(const Config& cfg, HttpClient& http, const CrawlResult& crawl) {
  (void)crawl;
  std::vector<Finding> findings;
  auto resp = http.get("https://" + cfg.target + "/favicon.ico");
  if (resp.status_code == 200 && resp.body.size() > 0) {
    // Simple hash for tech detection
    unsigned int hash = 0;
    for (char c : resp.body) hash = hash * 31 + (unsigned char)c;
    findings.push_back({"Favicon Hash", "info", "https://" + cfg.target + "/favicon.ico", "", "",
                        "Hash: " + std::to_string(hash) + " (use Shodan to identify technology)", ""});
  }
  return findings;
}

// 7. CIDR/ASN neighbors
std::vector<Finding> scan_cidr(const Config& cfg, HttpClient& http, const CrawlResult& crawl) {
  (void)crawl;
  (void)http;
  (void)cfg;
  // Would need IP resolution + range scan — skip for now (needs async DNS)
  return {};
}

// 8. Sitemap parser
std::vector<Finding> scan_sitemap(const Config& cfg, HttpClient& http, const CrawlResult& crawl) {
  (void)crawl;
  std::vector<Finding> findings;
  auto resp = http.get("https://" + cfg.target + "/sitemap.xml");
  if (resp.status_code == 200 && resp.body.find("<url>") != std::string::npos) {
    // Count URLs and check for interesting paths
    int count = 0;
    size_t pos = 0;
    while ((pos = resp.body.find("<loc>", pos)) != std::string::npos) {
      count++;
      pos += 5;
    }
    // Check for admin/api paths in sitemap
    if (resp.body.find("/admin") != std::string::npos || resp.body.find("/api") != std::string::npos) {
      findings.push_back({"Sitemap Reveals Sensitive Paths", "low", "https://" + cfg.target + "/sitemap.xml", "", "",
                          std::to_string(count) + " URLs, contains admin/api paths", ""});
    }
  }
  return findings;
}

// 9. Security.txt
std::vector<Finding> scan_security_txt(const Config& cfg, HttpClient& http, const CrawlResult& crawl) {
  (void)crawl;
  std::vector<Finding> findings;
  for (auto& path : {"/.well-known/security.txt", "/security.txt"}) {
    auto resp = http.get("https://" + cfg.target + path);
    if (resp.status_code == 200 && resp.body.find("Contact") != std::string::npos) {
      findings.push_back({"security.txt Found", "info", "https://" + cfg.target + path, "", "", resp.body.substr(0, 200), ""});
      break;
    }
  }
  return findings;
}

// 10. HTTP/2 request smuggling indicator
std::vector<Finding> scan_h2_smuggling(const Config& cfg, HttpClient& http, const CrawlResult& crawl) {
  (void)crawl;
  std::vector<Finding> findings;
  // Check if server supports HTTP/2 and has a frontend/backend mismatch indicator
  auto resp = http.get("https://" + cfg.target);
  if (resp.headers.count("via") || resp.headers.count("x-served-by")) {
    findings.push_back({"Proxy Detected (H2 Smuggling Candidate)", "info", "https://" + cfg.target, "", "",
                        "Via/X-Served-By header present — test for HTTP/2 request smuggling", ""});
  }
  return findings;
}

}  // namespace

std::vector<Scanner> register_recon_extra_scanners() {
  return {
      {"Subdomain Takeover", scan_subdomain_takeover},
      {"SSL/TLS Issues", scan_ssl_issues},
      {"Broken Link Hijacking", scan_broken_links},
      {"S3 Bucket Write", scan_s3_write},
      {"JS Secret Scanner", scan_js_secrets},
      {"Favicon Fingerprint", scan_favicon},
      {"Sitemap Analysis", scan_sitemap},
      {"Security.txt", scan_security_txt},
      {"H2 Smuggling Indicator", scan_h2_smuggling},
  };
}

}  // namespace apex
