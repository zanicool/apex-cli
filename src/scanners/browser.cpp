/// @file scanners/browser.cpp
/// @brief Browser-based scanners: browser-confirmed XSS, DOM XSS detection,
///        postMessage vulnerabilities.
#include "scanner_base.hpp"
#include "../proc.hpp"
#include <cstdio>

namespace apex {
namespace {

/// Find Chrome/Chromium binary path.
std::string find_chrome() {
  const char *paths[] = {
      "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
      "/usr/bin/google-chrome", "/usr/bin/chromium-browser",
      "/usr/bin/chromium", "/snap/bin/chromium"};
  for (const auto &p : paths) {
    FILE *f = fopen(p, "r");
    if (f) { fclose(f); return p; }
  }
  return "";
}

/// DOM XSS detection — find dangerous sinks in JavaScript.
std::vector<Finding> scan_dom_xss(const Config &, HttpClient &http,
                                  const CrawlResult &crawl) {
  std::vector<Finding> findings;
  const std::vector<std::string> sinks = {
      "innerHTML", "outerHTML", "document.write", "eval(",
      ".src=", "location.href=", "location.assign", "location.replace",
      "setTimeout(", "setInterval(", "Function("};
  const std::vector<std::string> sources = {
      "location.hash", "location.search", "location.href",
      "document.URL", "document.referrer", "window.name",
      "document.cookie", "postMessage"};

  for (const auto &url : crawl.urls) {
    if (url.find(".js") == std::string::npos) continue;
    auto resp = http.get(url);
    if (resp.status_code != 200) continue;

    bool has_source = false, has_sink = false;
    std::string found_sink, found_source;
    for (const auto &src : sources) {
      if (resp.body.find(src) != std::string::npos) {
        has_source = true;
        found_source = src;
        break;
      }
    }
    for (const auto &sink : sinks) {
      if (resp.body.find(sink) != std::string::npos) {
        has_sink = true;
        found_sink = sink;
        break;
      }
    }
    if (has_source && has_sink) {
      findings.push_back({"DOM XSS", "high", url,
                          "Source: " + found_source + " → Sink: " + found_sink,
                          "", "", ""});
    }
  }
  return findings;
}

/// PostMessage vulnerability detection.
std::vector<Finding> scan_postmessage(const Config &, HttpClient &http,
                                      const CrawlResult &crawl) {
  std::vector<Finding> findings;
  for (const auto &url : crawl.urls) {
    auto resp = http.get(url);
    if (resp.status_code != 200) continue;

    // Check for postMessage listeners without origin check.
    bool has_listener = resp.body.find("addEventListener") != std::string::npos
                        && resp.body.find("message") != std::string::npos;
    if (!has_listener) continue;

    bool has_origin_check =
        resp.body.find("origin") != std::string::npos &&
        (resp.body.find("event.origin") != std::string::npos ||
         resp.body.find("e.origin") != std::string::npos);

    if (!has_origin_check) {
      findings.push_back({"PostMessage", "medium", url,
                          "Message listener without origin validation",
                          "", "", ""});
    }
  }
  return findings;
}

/// Browser-confirmed XSS — use headless Chrome to verify XSS fires.
std::vector<Finding> scan_browser_xss(const Config &cfg, HttpClient &http,
                                      const CrawlResult &crawl) {
  std::vector<Finding> findings;
  std::string chrome = find_chrome();
  if (chrome.empty()) return findings; // No browser available.

  const std::string payload = "<img src=x onerror=document.title='XSS'>";
  for (const auto &url : crawl.urls) {
    auto targets = get_targets(crawl, url, "q");
    for (const auto &[base, param] : targets) {
      // First check if reflection exists.
      auto resp = http.get(base + payload);
      if (resp.body.find("onerror") == std::string::npos) continue;

      // Verify with headless browser using safe argv exec (no shell).
      std::string test_url = base + payload;
      auto proc = run_command({chrome, "--headless", "--disable-gpu",
                               "--no-sandbox", "--dump-dom", test_url},
                              10, /*capture_stdout=*/true);
      bool fired = proc.spawned &&
                   proc.stdout_data.find("XSS") != std::string::npos;
      if (fired) {
        findings.push_back({"XSS (Browser)", "critical", url,
                            "Browser-confirmed XSS execution",
                            param, payload, ""});
      }
    }
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_browser_scanners() {
  return {
      {"DOM XSS", scan_dom_xss},
      {"PostMessage", scan_postmessage},
      {"XSS (Browser)", scan_browser_xss},
  };
}

} // namespace apex
