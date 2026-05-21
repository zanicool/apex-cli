/// @file scanners/deep_recon.cpp
/// @brief Deep reconnaissance: DNS brute-force, Wayback URL discovery,
///        Google dorking, metadata extraction, GitHub recon, robots/sitemap
///        mining, certificate transparency deep scan.
#include "scanner_base.hpp"
#include <fstream>
#include <set>
#include <sstream>

namespace apex {
namespace {

/// Load subdomain wordlist.
std::vector<std::string> load_subdomain_wordlist() {
  std::vector<std::string> words;
  // Iterate over targets.
  for (const auto &path : {"./wordlists/subdomains-10000.txt",
                            "../wordlists/subdomains-10000.txt"}) {
    std::ifstream f(path);
    if (!f.is_open()) continue;
    std::string line;
    while (std::getline(f, line)) {
      if (!line.empty() && line[0] != '#') words.push_back(line);
      if (words.size() >= 500) break; // Limit for speed.
    }
    break;
  }
  return words;
}

/// DNS brute-force subdomain enumeration.
/// Scanner implementation.
std::vector<Finding> scan_dns_bruteforce(const Config &cfg, HttpClient &http,
                                         const CrawlResult &) {
  std::vector<Finding> findings;
  auto wordlist = load_subdomain_wordlist();
  if (wordlist.empty()) return findings;

  std::string domain = cfg.target;
  if (domain.find("://") != std::string::npos)
    domain = domain.substr(domain.find("://") + 3);
  if (domain.find('/') != std::string::npos)
    domain = domain.substr(0, domain.find('/'));

  std::set<std::string> live;
  // Iterate over targets.
  for (const auto &word : wordlist) {
    std::string sub = word + "." + domain;
    auto resp = http.get("https://" + sub + "/");
    if (resp.status_code > 0 && resp.error.empty()) {
      live.insert(sub);
    } else {
      resp = http.get("http://" + sub + "/");
      if (resp.status_code > 0 && resp.error.empty())
        live.insert(sub);
    }
  }

  if (!live.empty()) {
    std::string detail = "Found " + std::to_string(live.size()) + " subdomains via brute-force:";
    int count = 0;
    for (const auto &s : live) {
      if (count++ < 20) detail += " " + s;
    }
    findings.push_back({"DNS Brute-Force Discovery", "info", domain,
                        detail, "", "", ""});
  }
  return findings;
}

/// Wayback Machine full URL discovery — find forgotten endpoints.
/// Scanner implementation.
std::vector<Finding> scan_wayback_urls(const Config &cfg, HttpClient &http,
                                       const CrawlResult &) {
  std::vector<Finding> findings;
  std::string domain = cfg.target;
  if (domain.find("://") != std::string::npos)
    domain = domain.substr(domain.find("://") + 3);
  if (domain.find('/') != std::string::npos)
    domain = domain.substr(0, domain.find('/'));

  std::string wb_url = "https://web.archive.org/cdx/search/cdx?url=" + domain +
                       "/*&output=text&fl=original&collapse=urlkey&limit=200";
  auto resp = http.get(wb_url);
  // Check response status.
  if (resp.status_code != 200) return findings;

  // Parse URLs and look for interesting patterns.
  std::set<std::string> interesting;
  const std::vector<std::string> patterns = {
      "admin", "backup", "staging", "test", "debug", "internal",
      "old", "beta", "dev", ".env", ".git", "config", "secret",
      "api/v", "swagger", "graphql", "phpmyadmin", "wp-admin",
      ".sql", ".zip", ".tar", ".bak", "jenkins", "jira", "confluence"};

  std::istringstream stream(resp.body);
  std::string line;
  while (std::getline(stream, line)) {
    if (line.empty()) continue;
    for (const auto &p : patterns) {
      if (line.find(p) != std::string::npos) {
        interesting.insert(line);
        break;
      }
    }
  }

  // Probe interesting URLs to see if they're still live.
  std::vector<std::string> still_live;
  // Iterate over targets.
  for (const auto &url : interesting) {
    auto probe = http.get(url);
    if (probe.status_code == 200 && probe.body.size() > 50)
      still_live.push_back(url);
    if (still_live.size() >= 10) break;
  }

  if (!still_live.empty()) {
    std::string detail = "Wayback URLs still live:";
    for (const auto &u : still_live) detail += "\n  " + u;
    findings.push_back({"Wayback URL Discovery", "medium", domain,
                        detail, "", "", ""});
  }

  if (!interesting.empty()) {
    findings.push_back({"Wayback Historical URLs", "info", domain,
                        std::to_string(interesting.size()) +
                            " interesting historical URLs found in Wayback Machine",
                        "", "", ""});
  }
  return findings;
}

/// Google dorking — automated search for exposed files/pages.
/// Scanner implementation.
std::vector<Finding> scan_google_dorks(const Config &cfg, HttpClient &http,
                                       const CrawlResult &) {
  std::vector<Finding> findings;
  std::string domain = cfg.target;
  if (domain.find("://") != std::string::npos)
    domain = domain.substr(domain.find("://") + 3);
  if (domain.find('/') != std::string::npos)
    domain = domain.substr(0, domain.find('/'));

  struct Dork { const char *query; const char *desc; const char *severity; };
  const Dork dorks[] = {
      {"site:%s filetype:env", "Exposed .env files", "critical"},
      {"site:%s filetype:sql", "Exposed SQL dumps", "critical"},
      {"site:%s filetype:log", "Exposed log files", "high"},
      {"site:%s filetype:pdf confidential", "Confidential PDFs", "medium"},
      {"site:%s inurl:admin", "Admin panels indexed", "medium"},
      {"site:%s inurl:backup", "Backup files indexed", "high"},
      {"site:%s inurl:swagger", "Swagger/API docs indexed", "low"},
      {"site:%s inurl:graphql", "GraphQL endpoints indexed", "medium"},
      {"site:%s ext:xml sitemap", "Sitemaps indexed", "info"},
      {"site:%s \"internal use only\"", "Internal documents indexed", "medium"},
      {"site:%s inurl:jira", "Jira pages indexed", "medium"},
      {"site:%s inurl:confluence", "Confluence pages indexed", "medium"},
  };

  // Iterate over targets.
  for (const auto &dork : dorks) {
    char query[256];
    snprintf(query, sizeof(query), dork.query, domain.c_str());
    std::string url = std::string("https://www.google.com/search?q=") + query + "&num=5";
    auto resp = http.get(url);
    // Check if there are actual results (not "no results found").
    if (resp.status_code == 200 && resp.body.size() > 1000 &&
        resp.body.find("did not match any documents") == std::string::npos &&
        resp.body.find(domain) != std::string::npos) {
      findings.push_back({"Google Dork: " + std::string(dork.desc), dork.severity,
                          url, std::string(dork.desc) + " — query: " + query,
                          "", "", ""});
    }
  }
  return findings;
}

/// Metadata extraction from PDF/DOCX files found during crawl.
/// Scanner implementation.
std::vector<Finding> scan_metadata(const Config &, HttpClient &http,
                                   const CrawlResult &crawl) {
  std::vector<Finding> findings;

  // Find document URLs from crawl.
  std::set<std::string> doc_urls;
  // Iterate over targets.
  for (const auto &url : crawl.urls) {
    if (url.find(".pdf") != std::string::npos ||
        url.find(".docx") != std::string::npos ||
        url.find(".xlsx") != std::string::npos ||
        url.find(".pptx") != std::string::npos)
      doc_urls.insert(url);
  }

  // Also check common document paths.
  if (!crawl.urls.empty()) {
    std::string base = base_url_from(crawl.urls[0]);
    for (const auto &path : {"/annual-report.pdf", "/privacy-policy.pdf",
                              "/terms.pdf", "/brochure.pdf"}) {
      auto resp = http.get(base + path);
      if (resp.status_code == 200 && resp.body.size() > 1000)
        doc_urls.insert(base + path);
    }
  }

  // Iterate over targets.
  for (const auto &url : doc_urls) {
    auto resp = http.get(url);
    if (resp.status_code != 200) continue;

    // Extract PDF metadata (Creator, Producer, Author).
    const std::vector<std::string> meta_keys = {
        "/Author", "/Creator", "/Producer", "/Company",
        "dc:creator", "meta:author"};

    for (const auto &key : meta_keys) {
      size_t pos = resp.body.find(key);
      if (pos != std::string::npos && pos + key.size() + 2 < resp.body.size()) {
        // Extract value after the key.
        size_t start = pos + key.size();
        // Skip whitespace/parens.
        while (start < resp.body.size() &&
               (resp.body[start] == ' ' || resp.body[start] == '(' ||
                resp.body[start] == '>'))
          start++;
        size_t end = start;
        while (end < resp.body.size() && end - start < 100 &&
               resp.body[end] != ')' && resp.body[end] != '<' &&
               resp.body[end] != '\0')
          end++;
        std::string value = resp.body.substr(start, end - start);
        if (value.size() > 2 && value.size() < 80) {
          findings.push_back({"Document Metadata: " + key, "info", url,
                              "Metadata " + key + " = " + value, "", "", ""});
          break; // One finding per doc is enough.
        }
      }
    }

    // Check for internal paths in PDF (C:\Users\..., /home/...)
    std::regex path_re(R"((?:C:\\Users\\[^\s\\]+|/home/[a-z]+))");
    std::smatch m;
    if (std::regex_search(resp.body, m, path_re)) {
      findings.push_back({"Internal Path in Document", "low", url,
                          "Internal filesystem path leaked: " + m[0].str(),
                          "", "", ""});
    }
  }
  return findings;
}

/// GitHub recon — search for leaked code/secrets related to target.
/// Scanner implementation.
std::vector<Finding> scan_github_recon(const Config &cfg, HttpClient &http,
                                       const CrawlResult &) {
  std::vector<Finding> findings;
  std::string domain = cfg.target;
  if (domain.find("://") != std::string::npos)
    domain = domain.substr(domain.find("://") + 3);
  if (domain.find('/') != std::string::npos)
    domain = domain.substr(0, domain.find('/'));

  // Search GitHub code for references to this domain.
  const std::vector<std::pair<std::string, std::string>> searches = {
      {domain + " password", "Passwords referencing domain"},
      {domain + " api_key", "API keys referencing domain"},
      {domain + " secret", "Secrets referencing domain"},
      {domain + " token", "Tokens referencing domain"},
  };

  // Iterate over targets.
  for (const auto &[query, desc] : searches) {
    std::string url = "https://github.com/search?q=" + query + "&type=code";
    auto resp = http.get(url);
    if (resp.status_code == 200 &&
        resp.body.find("code-list") != std::string::npos &&
        resp.body.find("We couldn") == std::string::npos) {
      findings.push_back({"GitHub Code Leak: " + desc, "high", url,
                          desc + " found on GitHub", "", "", ""});
    }
  }
  return findings;
}

/// robots.txt and sitemap.xml mining.
/// Scanner implementation.
std::vector<Finding> scan_robots_sitemap(const Config &, HttpClient &http,
                                         const CrawlResult &crawl) {
  std::vector<Finding> findings;
  // Early return if no URLs to scan.
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // robots.txt — look for disallowed paths that reveal structure.
  auto robots = http.get(base + "/robots.txt");
  if (robots.status_code == 200 && robots.body.size() > 10) {
    std::vector<std::string> interesting_disallows;
    std::istringstream stream(robots.body);
    std::string line;
    while (std::getline(stream, line)) {
      if (line.find("Disallow:") != std::string::npos) {
        std::string path = line.substr(line.find(':') + 1);
        while (!path.empty() && path[0] == ' ') path = path.substr(1);
        if (path.find("admin") != std::string::npos ||
            path.find("api") != std::string::npos ||
            path.find("internal") != std::string::npos ||
            path.find("debug") != std::string::npos ||
            path.find("backup") != std::string::npos ||
            path.find("staging") != std::string::npos) {
          interesting_disallows.push_back(path);
        }
      }
    }

    if (!interesting_disallows.empty()) {
      std::string detail = "Interesting disallowed paths:";
      for (const auto &p : interesting_disallows) detail += " " + p;
      findings.push_back({"robots.txt Intel", "info", base + "/robots.txt",
                          detail, "", "", ""});

      // Probe disallowed paths.
      for (const auto &path : interesting_disallows) {
        auto resp = http.get(base + path);
        if (resp.status_code == 200 && resp.body.size() > 100) {
          findings.push_back({"Disallowed Path Accessible", "medium", base + path,
                              "robots.txt disallowed path is actually accessible",
                              "", "", ""});
        }
      }
    }
  }

  // sitemap.xml — discover all indexed URLs.
  auto sitemap = http.get(base + "/sitemap.xml");
  if (sitemap.status_code == 200 && sitemap.body.find("<loc>") != std::string::npos) {
    // Count URLs and look for interesting ones.
    std::regex loc_re(R"(<loc>([^<]+)</loc>)");
    auto begin = std::sregex_iterator(sitemap.body.begin(), sitemap.body.end(), loc_re);
    auto end = std::sregex_iterator();
    int count = 0;
    for (auto it = begin; it != end; ++it) count++;
    if (count > 0) {
      findings.push_back({"Sitemap Discovery", "info", base + "/sitemap.xml",
                          "Sitemap contains " + std::to_string(count) + " URLs",
                          "", "", ""});
    }
  }
  return findings;
}

/// Certificate transparency deep — find historical/expired subdomains.
/// Scanner implementation.
std::vector<Finding> scan_ct_deep(const Config &cfg, HttpClient &http,
                                  const CrawlResult &) {
  std::vector<Finding> findings;
  std::string domain = cfg.target;
  if (domain.find("://") != std::string::npos)
    domain = domain.substr(domain.find("://") + 3);
  if (domain.find('/') != std::string::npos)
    domain = domain.substr(0, domain.find('/'));

  // Query crt.sh for expired/historical certs.
  std::string url = "https://crt.sh/?q=%25." + domain + "&output=json&expired=true";
  auto resp = http.get(url);
  // Check response status.
  if (resp.status_code != 200) return findings;

  std::set<std::string> all_subs;
  std::regex name_re(R"re("common_name"\s*:\s*"([^"]+)")re");
  auto it_begin = std::sregex_iterator(resp.body.begin(), resp.body.end(), name_re);
  auto it_end = std::sregex_iterator();
  for (auto it = it_begin; it != it_end; ++it) {
    std::string sub = (*it)[1].str();
    if (sub.size() > 2 && sub.substr(0, 2) == "*.") sub = sub.substr(2);
    all_subs.insert(sub);
  }

  // Check for potential subdomain takeover on expired/dangling subs.
  std::vector<std::string> dangling;
  // Iterate over targets.
  for (const auto &sub : all_subs) {
    auto probe = http.get("https://" + sub + "/");
    if (probe.status_code == 0 || !probe.error.empty()) {
      // DNS resolves but no HTTP = potential takeover.
      dangling.push_back(sub);
    }
    if (dangling.size() >= 5) break;
  }

  if (!dangling.empty()) {
    std::string detail = "Potentially dangling subdomains (takeover risk):";
    for (const auto &d : dangling) detail += " " + d;
    findings.push_back({"CT Dangling Subdomains", "medium", domain,
                        detail, "", "", ""});
  }

  if (all_subs.size() > 10) {
    findings.push_back({"CT Historical Subdomains", "info", domain,
                        std::to_string(all_subs.size()) +
                            " total subdomains found in certificate transparency logs",
                        "", "", ""});
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_deep_recon_scanners() {
  return {
      {"DNS Brute-Force", scan_dns_bruteforce},
      {"Wayback URLs", scan_wayback_urls},
      {"Google Dorks", scan_google_dorks},
      {"Document Metadata", scan_metadata},
      {"GitHub Recon", scan_github_recon},
      {"robots.txt/Sitemap", scan_robots_sitemap},
      {"CT Deep Scan", scan_ct_deep},
  };
}

} // namespace apex
