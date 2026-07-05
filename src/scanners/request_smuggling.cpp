/// @file scanners/request_smuggling.cpp
/// @brief HTTP Request Smuggling (HRS) scanner: CL.TE, TE.CL, TE.TE desync,
///        H2.CL downgrade, and cache poisoning via smuggling.
#include "scanner_base.hpp"
#include <regex>
#include <chrono>

namespace apex {
namespace {

/// Detect CL.TE smuggling via timing differential.
std::vector<Finding> scan_clte_smuggling(const Config &, HttpClient &http,
                                          const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Baseline timing
  auto start = std::chrono::steady_clock::now();
  http.post(base + "/", "x=1", "application/x-www-form-urlencoded");
  auto baseline_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                         std::chrono::steady_clock::now() - start).count();

  // CL.TE probe: Content-Length shorter than chunked body
  std::string smuggle_body = "0\r\n\r\n";
  start = std::chrono::steady_clock::now();
  http.post(base + "/", smuggle_body, "application/x-www-form-urlencoded",
            {{"Content-Length", "4"}, {"Transfer-Encoding", "chunked"}});
  auto probe_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now() - start).count();

  if (probe_ms > baseline_ms + 5000) {
    findings.push_back(Finding{"HTTP Request Smuggling — CL.TE Desync", "critical", base,
                        "Server exhibits timing differential with ambiguous CL/TE headers. "
                        "Front-end uses Content-Length, back-end uses Transfer-Encoding. "
                        "Enables request smuggling: poison other users' requests, bypass WAF, "
                        "steal credentials, and cache poisoning.",
                        "", "",
                        "Baseline: " + std::to_string(baseline_ms) + "ms, "
                        "Probe: " + std::to_string(probe_ms) + "ms"});
  }

  return findings;
}

/// Detect TE.CL smuggling via timing.
std::vector<Finding> scan_tecl_smuggling(const Config &, HttpClient &http,
                                          const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  std::string body = "1\r\nZ\r\n0\r\n\r\n";

  auto start = std::chrono::steady_clock::now();
  http.post(base + "/", body, "application/x-www-form-urlencoded",
            {{"Transfer-Encoding", "chunked"},
             {"Content-Length", std::to_string(body.size() + 100)}});
  auto probe_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now() - start).count();

  if (probe_ms > 5000) {
    findings.push_back(Finding{"HTTP Request Smuggling — TE.CL Desync", "critical", base,
                        "Server times out with TE body + inflated Content-Length. "
                        "Enables full request smuggling attack chain.",
                        "", "", "Probe timed out at " + std::to_string(probe_ms) + "ms"});
  }

  return findings;
}

/// Detect TE.TE smuggling via obfuscated Transfer-Encoding headers.
std::vector<Finding> scan_tete_smuggling(const Config &, HttpClient &http,
                                          const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  std::vector<std::pair<std::string, std::string>> te_variants = {
      {"Transfer-Encoding", " chunked"},
      {"Transfer-Encoding", "chunked "},
      {"Transfer-Encoding", "\tchunked"},
      {"Transfer-encoding", "chunked"},
      {"Transfer-Encoding", "identity, chunked"},
  };

  std::string body = "0\r\n\r\n";

  for (const auto &[header, value] : te_variants) {
    auto resp = http.post(base + "/", body, "application/x-www-form-urlencoded",
                          {{header, value}, {"Content-Length", "5"}});

    if (resp.status_code == 400 || resp.status_code == 501) {
      findings.push_back(Finding{"HTTP Request Smuggling — TE Obfuscation Differential", "high", base,
                          "Server rejects obfuscated TE variant: '" + value + "'. "
                          "If a front-end proxy accepts this variant, TE.TE desync is possible.",
                          header, value, "Status: " + std::to_string(resp.status_code)});
      break;
    }
  }

  return findings;
}

/// Detect HTTP/2 downgrade smuggling potential.
std::vector<Finding> scan_h2_smuggling(const Config &, HttpClient &http,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  auto resp = http.get(base);
  bool has_h2 = false;
  for (const auto &[key, val] : resp.headers) {
    std::string lower = key;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower == "alt-svc" && val.find("h2") != std::string::npos) has_h2 = true;
  }

  auto server = resp.headers.find("server");
  if (server != resp.headers.end()) {
    if (server->second.find("nginx") != std::string::npos ||
        server->second.find("cloudflare") != std::string::npos) {
      has_h2 = true;
    }
  }

  if (has_h2) {
    auto probe = http.post(base + "/", "x", "text/plain",
                           {{"Content-Length", "0"}});
    if (probe.status_code == 200 && probe.body != resp.body) {
      findings.push_back(Finding{"HTTP/2 Downgrade — Potential H2.CL Smuggling", "high", base,
                          "Server supports HTTP/2 and may be vulnerable to H2.CL smuggling.",
                          "", "", ""});
    }
  }

  return findings;
}

} // namespace

std::vector<Scanner> register_request_smuggling_scanners() {
  return {
      {"CL.TE Smuggling", scan_clte_smuggling},
      {"TE.CL Smuggling", scan_tecl_smuggling},
      {"TE.TE Obfuscation", scan_tete_smuggling},
      {"H2 Downgrade", scan_h2_smuggling},
  };
}

} // namespace apex
