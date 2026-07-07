/// @file scanners/leak_intel.cpp
/// @brief Leak intelligence: credential exposure checks, paste site monitoring,
///        GitHub secret scanning, infostealer log indicators, ransomware leak
///        site monitoring, API key exposure, brand/phishing detection.
///
/// Uses only public/legal OSINT sources:
///   - HIBP (breach check)
///   - GitHub code search (leaked secrets)
///   - Paste sites (public pastes)
///   - LeakIX (exposed services)
///   - crt.sh (certificate transparency)
///   - Google dorking (indexed leaks)
///   - Shodan (exposed infra)
#include <set>

#include "scanner_base.hpp"

namespace apex {
namespace {

/// Extract domain from config target.
std::string get_domain(const Config& cfg) {
  std::string d = cfg.target;
  if (d.find("://") != std::string::npos) d = d.substr(d.find("://") + 3);
  if (d.find('/') != std::string::npos) d = d.substr(0, d.find('/'));
  if (d.find(':') != std::string::npos) d = d.substr(0, d.find(':'));
  return d;
}

/// GitHub code search for leaked secrets.
std::vector<Finding> scan_github_leaks(const Config& cfg, HttpClient& http, const CrawlResult&) {
  std::vector<Finding> findings;
  std::string domain = get_domain(cfg);
  std::string org = domain.substr(0, domain.find('.'));

  // GitHub code search queries (public, no auth needed for basic search).
  const std::vector<std::pair<std::string, std::string>> queries = {
      {"\"" + domain + "\" password", "Password in code"},
      {"\"" + domain + "\" api_key", "API key in code"},
      {"\"" + domain + "\" secret", "Secret in code"},
      {"\"" + domain + "\" token", "Token in code"},
      {"\"" + domain + "\" AWS_ACCESS_KEY", "AWS key in code"},
      {"\"" + domain + "\" PRIVATE_KEY", "Private key in code"},
      {"org:" + org + " filename:.env", ".env file in org repos"},
      {"org:" + org + " filename:id_rsa", "SSH key in org repos"},
      {"org:" + org + " filename:credentials", "Credentials file in org repos"},
  };

  for (const auto& [query, desc] : queries) {
    std::string url = "https://github.com/search?q=" + query + "&type=code";
    auto resp = http.get(url);
    if (resp.status_code == 200 && resp.body.find("code-list") != std::string::npos && resp.body.find("We couldn") == std::string::npos) {
      findings.push_back({"GitHub Secret Leak", "critical", url, desc + " — found on GitHub", "", query, ""});
    }
  }
  return findings;
}

/// Check paste sites for leaked data.
std::vector<Finding> scan_paste_leaks(const Config& cfg, HttpClient& http, const CrawlResult&) {
  std::vector<Finding> findings;
  std::string domain = get_domain(cfg);

  // Search via Google for paste site leaks.
  const std::vector<std::string> paste_dorks = {
      "site:pastebin.com \"" + domain + "\"", "site:paste.ee \"" + domain + "\"",     "site:ghostbin.co \"" + domain + "\"",
      "site:dpaste.org \"" + domain + "\"",   "site:justpaste.it \"" + domain + "\"", "site:rentry.co \"" + domain + "\"",
  };

  for (const auto& dork : paste_dorks) {
    std::string url = "https://www.google.com/search?q=" + dork;
    auto resp = http.get(url);
    if (resp.status_code == 200 && resp.body.find("did not match") == std::string::npos && resp.body.find("result") != std::string::npos &&
        resp.body.find(domain) != std::string::npos) {
      findings.push_back({"Paste Site Leak", "high", url, "Domain mentioned on paste site — possible credential dump", "", dork, ""});
    }
  }
  return findings;
}

/// Check credential breach databases (HIBP-style).
std::vector<Finding> scan_credential_exposure(const Config& cfg, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  std::string domain = get_domain(cfg);
  std::string base = crawl.urls.empty() ? "https://" + domain : base_url_from(crawl.urls[0]);

  // 1. Harvest emails from the target.
  std::set<std::string> emails;
  std::regex email_re("[a-zA-Z0-9._%+\\-]+@" + domain);
  const std::vector<std::string> pages = {"/", "/contact", "/about", "/team"};
  for (const auto& path : pages) {
    auto resp = http.get(base + path);
    std::sregex_iterator it(resp.body.begin(), resp.body.end(), email_re);
    for (; it != std::sregex_iterator(); ++it) emails.insert((*it)[0].str());
  }
  // Add common patterns.
  for (const auto& p : {"info", "admin", "contact", "support", "hr", "security"}) emails.insert(std::string(p) + "@" + domain);

  // 2. Check HIBP for each email.
  for (const auto& email : emails) {
    auto resp = http.get("https://haveibeenpwned.com/api/v3/breachedaccount/" + email);
    if (resp.status_code == 200 && resp.body.find("Name") != std::string::npos) {
      // Count breaches.
      int count = 0;
      size_t pos = 0;
      while ((pos = resp.body.find("\"Name\"", pos)) != std::string::npos) {
        count++;
        pos++;
      }
      findings.push_back({"Credential Breach", "high", "https://haveibeenpwned.com/account/" + email,
                          email + " found in " + std::to_string(count) + " breach(es)", "", email, ""});
    }
  }

  // 3. Check domain-level breach via HIBP domain search.
  auto domain_resp = http.get("https://haveibeenpwned.com/api/v3/breaches?domain=" + domain);
  if (domain_resp.status_code == 200 && domain_resp.body.size() > 10 && domain_resp.body.find("Name") != std::string::npos) {
    findings.push_back({"Domain Breach History", "high", "https://haveibeenpwned.com",
                        "Domain " + domain + " appears in known data breaches", "", domain, ""});
  }

  return findings;
}

/// Check for exposed API keys and secrets in public sources.
std::vector<Finding> scan_api_key_exposure(const Config& cfg, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);
  std::string domain = get_domain(cfg);

  // Check JS files for hardcoded keys.
  std::regex js_re(R"(src=["']([^"']+\.js)["'])");
  auto home = http.get(base + "/");
  std::set<std::string> js_urls;
  auto jit = std::sregex_iterator(home.body.begin(), home.body.end(), js_re);
  for (; jit != std::sregex_iterator(); ++jit) {
    std::string js_path = (*jit)[1].str();
    if (js_path.find("http") == 0)
      js_urls.insert(js_path);
    else
      js_urls.insert(base + (js_path[0] == '/' ? "" : "/") + js_path);
  }

  // Key patterns to detect.
  struct KeyPattern {
    const char* name;
    const char* regex;
    const char* severity;
  };
  const KeyPattern patterns[] = {
      {"AWS Access Key", R"(AKIA[0-9A-Z]{16})", "critical"},
      {"AWS Secret Key", R"((?:aws_secret|secret_key).*?['\"][0-9a-zA-Z/+=]{40}['\"])", "critical"},
      {"Google API Key", R"(AIza[0-9A-Za-z\-_]{35})", "high"},
      {"Stripe Secret Key", R"(sk_live_[0-9a-zA-Z]{24,})", "critical"},
      {"Stripe Publishable", R"(pk_live_[0-9a-zA-Z]{24,})", "medium"},
      {"GitHub Token", R"(gh[ps]_[A-Za-z0-9_]{36,})", "critical"},
      {"Slack Token", R"(xox[baprs]-[0-9a-zA-Z\-]{10,})", "critical"},
      {"Firebase Key", R"(AIza[0-9A-Za-z\-_]{35})", "high"},
      {"JWT Secret", R"((?:jwt_secret|JWT_SECRET).*?['\"][^'\"]{16,}['\"])", "critical"},
      {"Private Key", R"(-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)", "critical"},
      {"SendGrid Key", R"(SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})", "critical"},
      {"Twilio SID", R"(AC[a-z0-9]{32})", "high"},
      {"OpenAI Key", R"(sk-[A-Za-z0-9]{48})", "critical"},
      {"Mailgun Key", R"(key-[0-9a-zA-Z]{32})", "high"},
  };

  // Scan JS files.
  size_t js_limit = std::min(js_urls.size(), size_t(20));
  size_t js_count = 0;
  for (const auto& js_url : js_urls) {
    if (++js_count > js_limit) break;
    auto resp = http.get(js_url);
    if (resp.status_code != 200) continue;
    for (const auto& pat : patterns) {
      std::regex re(pat.regex);
      if (std::regex_search(resp.body, re)) {
        findings.push_back(
            {"Exposed " + std::string(pat.name), pat.severity, js_url, std::string(pat.name) + " found in JavaScript file", "", "", ""});
        break;  // One finding per file is enough.
      }
    }
  }

  // Also check the homepage source.
  for (const auto& pat : patterns) {
    std::regex re(pat.regex);
    if (std::regex_search(home.body, re)) {
      findings.push_back(
          {"Exposed " + std::string(pat.name), pat.severity, base, std::string(pat.name) + " found in page source", "", "", ""});
    }
  }

  return findings;
}

/// Brand monitoring: phishing domains, typosquatting, fake login pages.
std::vector<Finding> scan_brand_exposure(const Config& cfg, HttpClient& http, const CrawlResult&) {
  std::vector<Finding> findings;
  std::string domain = get_domain(cfg);
  std::string name = domain.substr(0, domain.find('.'));

  // 1. Check certificate transparency for suspicious lookalike domains.
  auto ct = http.get("https://crt.sh/?q=%25" + name + "%25&output=json&exclude=expired");
  if (ct.status_code == 200 && ct.body.size() > 100) {
    // Look for domains that aren't ours.
    std::regex domain_re("\"common_name\":\"([^\"]+)\"");
    std::set<std::string> suspicious;
    auto dit = std::sregex_iterator(ct.body.begin(), ct.body.end(), domain_re);
    for (; dit != std::sregex_iterator(); ++dit) {
      std::string found = (*dit)[1].str();
      if (found.find(domain) == std::string::npos && found.find(name) != std::string::npos) suspicious.insert(found);
    }
    if (!suspicious.empty()) {
      std::string detail = std::to_string(suspicious.size()) + " lookalike domain(s) found: ";
      int shown = 0;
      for (const auto& s : suspicious) {
        if (++shown > 5) {
          detail += "...";
          break;
        }
        detail += s + ", ";
      }
      findings.push_back({"Typosquatting/Phishing Domains", "high", "https://crt.sh/?q=%25" + name + "%25", detail, "", "", ""});
    }
  }

  // 2. Check for ransomware leak site mentions (via Google).
  std::string ransom_dork = "\"" + domain + "\" site:*.onion.ws OR site:ransomwatch.telemetry.ltd";
  auto ransom = http.get("https://www.google.com/search?q=" + ransom_dork);
  if (ransom.status_code == 200 && ransom.body.find(domain) != std::string::npos &&
      ransom.body.find("did not match") == std::string::npos) {
    findings.push_back({"Ransomware Mention", "critical", "https://www.google.com/search?q=" + ransom_dork,
                        "Domain possibly mentioned on ransomware leak site", "", "", ""});
  }

  return findings;
}

/// Check for infostealer indicators and session exposure.
std::vector<Finding> scan_infostealer_indicators(const Config& cfg, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);
  std::string domain = get_domain(cfg);

  // 1. Check if session cookies lack proper protections (stealer-friendly).
  auto resp = http.get(base + "/");
  for (const auto& [name, value] : resp.headers) {
    if (name != "Set-Cookie") continue;
    bool session_cookie = (value.find("session") != std::string::npos || value.find("PHPSESSID") != std::string::npos ||
                           value.find("JSESSIONID") != std::string::npos || value.find("connect.sid") != std::string::npos ||
                           value.find("_token") != std::string::npos);
    if (!session_cookie) continue;

    std::string issues;
    if (value.find("HttpOnly") == std::string::npos) issues += "no HttpOnly, ";
    if (value.find("Secure") == std::string::npos) issues += "no Secure, ";
    if (value.find("SameSite") == std::string::npos) issues += "no SameSite, ";
    if (value.find("__Host-") == std::string::npos && value.find("__Secure-") == std::string::npos) issues += "no cookie prefix, ";

    // Check for long expiry (stealer-friendly).
    if (value.find("Max-Age=") != std::string::npos) {
      std::regex age_re(R"(Max-Age=(\d+))");
      std::smatch am;
      if (std::regex_search(value, am, age_re)) {
        long age = std::stol(am[1].str());
        if (age > 86400 * 30)  // > 30 days
          issues += "long-lived (" + std::to_string(age / 86400) + " days), ";
      }
    }

    if (!issues.empty()) {
      findings.push_back({"Session Theft Risk", "high", base, "Session cookie vulnerable to infostealer theft: " + issues, "", "", ""});
    }
  }

  // 2. Check if device binding / conditional access is absent.
  // No device fingerprint headers = easier session replay.
  auto login_paths = {"/login", "/signin", "/auth/login", "/api/auth/login"};
  for (const auto& path : login_paths) {
    auto login_resp = http.get(base + path);
    if (login_resp.status_code != 200) continue;
    if (login_resp.body.find("device") == std::string::npos && login_resp.body.find("fingerprint") == std::string::npos &&
        login_resp.body.find("mfa") == std::string::npos && login_resp.body.find("2fa") == std::string::npos) {
      findings.push_back({"No Device Binding", "medium", base + path,
                          "Login page shows no MFA/device binding — "
                          "stolen sessions can be replayed from any device",
                          "", "", ""});
      break;
    }
  }

  return findings;
}

}  // namespace

std::vector<Scanner> register_leak_intel_scanners() {
  return {
      {"GitHub Secret Scan", scan_github_leaks},         {"Paste Site Leaks", scan_paste_leaks},
      {"Credential Exposure", scan_credential_exposure}, {"API Key Exposure", scan_api_key_exposure},
      {"Brand/Phishing Monitor", scan_brand_exposure},   {"Infostealer Risk", scan_infostealer_indicators},
  };
}

}  // namespace apex
