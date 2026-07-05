/// @file scanners/recon_advanced.cpp
/// @brief Advanced recon scanners: technology fingerprinting, WAF bypass probing,
///        API schema guessing, hidden admin panels, staging environment detection,
///        internal IP disclosure, email harvesting, social engineering surface,
///        JS library vulnerabilities, outdated framework detection, DNS misconfig,
///        SPF/DMARC weakness, exposed metrics, k8s/docker indicators, CI/CD leak.
#include "scanner_base.hpp"
#include <regex>
#include <set>

namespace apex {
namespace {

/// Internal IP address disclosure in response headers/body.
std::vector<Finding> scan_internal_ip(const Config &, HttpClient &http,
                                       const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  std::regex ip_re(R"((?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}))");

  for (const auto &url : crawl.urls) {
    auto resp = http.get(url);
    // Check headers
    for (const auto &[h, v] : resp.headers) {
      std::smatch m;
      if (std::regex_search(v, m, ip_re)) {
        findings.push_back({"Internal IP Disclosed (Header)", "low", url,
                            "Internal IP in header " + h + ": " + m[0].str(),
                            "", "", h + ": " + v.substr(0, 80)});
        return findings;
      }
    }
    // Check body
    std::smatch m;
    if (std::regex_search(resp.body, m, ip_re)) {
      findings.push_back({"Internal IP Disclosed (Body)", "low", url,
                          "Internal IP found in response: " + m[0].str(),
                          "", "", "IP: " + m[0].str()});
      return findings;
    }
    break; // Only check first URL
  }
  return findings;
}

/// Staging/test environment detection.
std::vector<Finding> scan_staging_env(const Config &cfg, HttpClient &http,
                                       const CrawlResult &) {
  std::vector<Finding> findings;
  const std::vector<std::string> prefixes = {
      "staging.", "stage.", "dev.", "test.", "uat.", "preprod.",
      "sandbox.", "demo.", "qa.", "beta.", "internal."};

  for (const auto &prefix : prefixes) {
    std::string subdomain = prefix + cfg.target;
    auto resp = http.get("https://" + subdomain);
    if (resp.status_code == 200 && resp.body.size() > 100) {
      findings.push_back({"Staging Environment Found", "medium",
                          "https://" + subdomain,
                          prefix.substr(0, prefix.size()-1) + " environment publicly accessible",
                          "", subdomain, std::to_string(resp.body.size()) + " bytes"});
    }
  }
  return findings;
}

/// Kubernetes/Docker indicators.
std::vector<Finding> scan_k8s_docker(const Config &, HttpClient &http,
                                      const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::pair<std::string, std::string>> k8s_paths = {
      {"/api/v1/namespaces", "Kubernetes API"},
      {"/apis", "Kubernetes APIs"},
      {"/healthz", "K8s Health"},
      {"/readyz", "K8s Ready"},
      {"/_/docker", "Docker"},
      {"/v2/_catalog", "Docker Registry"},
  };

  for (const auto &[path, name] : k8s_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 && resp.body.size() > 20) {
      if (path == "/v2/_catalog" && resp.body.find("repositories") != std::string::npos) {
        findings.push_back({"Docker Registry Open", "critical", base + path,
                            "Docker registry publicly accessible — images can be pulled",
                            "", "", resp.body.substr(0, 200)});
      } else if (path == "/api/v1/namespaces" && resp.body.find("items") != std::string::npos) {
        findings.push_back({"Kubernetes API Exposed", "critical", base + path,
                            "K8s API server accessible — cluster compromise possible",
                            "", "", ""});
      }
    }
  }
  return findings;
}

/// CI/CD artifact/config leak.
std::vector<Finding> scan_cicd_leak(const Config &, HttpClient &http,
                                     const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::pair<std::string, std::string>> ci_paths = {
      {"/.github/workflows/", "GitHub Actions"},
      {"/.gitlab-ci.yml", "GitLab CI"},
      {"/Jenkinsfile", "Jenkins"},
      {"/.circleci/config.yml", "CircleCI"},
      {"/.travis.yml", "Travis CI"},
      {"/bitbucket-pipelines.yml", "Bitbucket"},
      {"/Dockerfile", "Docker"},
      {"/docker-compose.yml", "Docker Compose"},
  };

  for (const auto &[path, name] : ci_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 && resp.body.size() > 20 &&
        resp.body.find("<html") == std::string::npos) {
      findings.push_back({"CI/CD Config Exposed: " + name, "medium", base + path,
                          name + " configuration publicly accessible",
                          "", "", std::to_string(resp.body.size()) + " bytes"});
    }
  }
  return findings;
}

/// Outdated JavaScript library detection.
std::vector<Finding> scan_js_libraries(const Config &, HttpClient &http,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  auto resp = http.get(crawl.urls[0]);

  struct LibCheck {
    std::string name;
    std::regex pattern;
    std::string vuln_below;
  };

  // Check for known vulnerable patterns in page source
  if (resp.body.find("jquery") != std::string::npos) {
    std::regex jq_re(R"(jquery[/\-]([12]\.\d+\.\d+))");
    std::smatch m;
    if (std::regex_search(resp.body, m, jq_re)) {
      std::string ver = m[1].str();
      if (ver[0] == '1' || (ver[0] == '2' && ver.size() > 2)) {
        findings.push_back({"Outdated jQuery: " + ver, "medium", crawl.urls[0],
                            "jQuery " + ver + " has known XSS vulnerabilities",
                            "", "", "CVE-2020-11022, CVE-2020-11023"});
      }
    }
  }
  if (resp.body.find("angular") != std::string::npos &&
      resp.body.find("angular.js") != std::string::npos) {
    findings.push_back({"AngularJS Detected", "low", crawl.urls[0],
                        "AngularJS (1.x) is end-of-life — template injection possible",
                        "", "", "Upgrade to Angular 2+"});
  }
  if (resp.body.find("lodash") != std::string::npos) {
    std::regex lodash_re(R"(lodash[/\-]([34]\.\d+\.\d+))");
    std::smatch m;
    if (std::regex_search(resp.body, m, lodash_re)) {
      findings.push_back({"Outdated Lodash: " + m[1].str(), "low", crawl.urls[0],
                          "Lodash " + m[1].str() + " has prototype pollution CVEs",
                          "", "", "CVE-2021-23337, CVE-2020-8203"});
    }
  }
  return findings;
}

/// SPF/DMARC email security check.
std::vector<Finding> scan_email_security(const Config &cfg, HttpClient &,
                                          const CrawlResult &) {
  std::vector<Finding> findings;

  // Check SPF
  std::string spf_cmd = "dig +short TXT " + cfg.target + " 2>/dev/null | grep spf";
  FILE *fp = popen(spf_cmd.c_str(), "r");
  if (fp) {
    char buf[1024] = {};
    fread(buf, 1, sizeof(buf) - 1, fp);
    pclose(fp);
    std::string spf(buf);
    if (spf.empty()) {
      findings.push_back({"Missing SPF Record", "medium", cfg.target,
                          "No SPF record — domain can be spoofed for phishing",
                          "", "", ""});
    } else if (spf.find("+all") != std::string::npos) {
      findings.push_back({"SPF +all (Permissive)", "high", cfg.target,
                          "SPF allows any server to send email as this domain",
                          "", "", spf.substr(0, 100)});
    }
  }

  // Check DMARC
  std::string dmarc_cmd = "dig +short TXT _dmarc." + cfg.target + " 2>/dev/null";
  fp = popen(dmarc_cmd.c_str(), "r");
  if (fp) {
    char buf[1024] = {};
    fread(buf, 1, sizeof(buf) - 1, fp);
    pclose(fp);
    std::string dmarc(buf);
    if (dmarc.empty() || dmarc.find("v=DMARC") == std::string::npos) {
      findings.push_back({"Missing DMARC Record", "medium", cfg.target,
                          "No DMARC policy — email spoofing not prevented",
                          "", "", ""});
    } else if (dmarc.find("p=none") != std::string::npos) {
      findings.push_back({"DMARC p=none", "low", cfg.target,
                          "DMARC in monitor-only mode — spoofed emails still delivered",
                          "", "", dmarc.substr(0, 100)});
    }
  }
  return findings;
}

/// Exposed Prometheus/Grafana metrics.
std::vector<Finding> scan_exposed_metrics(const Config &, HttpClient &http,
                                           const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> metric_paths = {
      "/metrics", "/prometheus", "/grafana", "/api/metrics",
      "/-/metrics", "/internal/metrics"};

  for (const auto &path : metric_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 &&
        (resp.body.find("# HELP") != std::string::npos ||
         resp.body.find("# TYPE") != std::string::npos ||
         resp.body.find("process_cpu") != std::string::npos)) {
      findings.push_back({"Prometheus Metrics Exposed", "medium", base + path,
                          "Application metrics publicly accessible — info disclosure",
                          "", "", std::to_string(resp.body.size()) + " bytes"});
      break;
    }
  }
  return findings;
}

/// Hidden admin panel discovery.
std::vector<Finding> scan_hidden_admin(const Config &, HttpClient &http,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> admin_paths = {
      "/admin.php", "/administrator/", "/admin123", "/cpanel",
      "/controlpanel", "/adminpanel", "/backend", "/cms",
      "/portal", "/webadmin", "/siteadmin", "/manage",
      "/supervisor", "/moderator", "/staff"};

  // Get 404 fingerprint
  auto not_found = http.get(base + "/definitely-not-a-real-page-xyz");

  for (const auto &path : admin_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 && resp.body.size() > 200 &&
        resp.body != not_found.body &&
        resp.body.find("login") != std::string::npos) {
      findings.push_back({"Hidden Admin Panel", "medium", base + path,
                          "Admin login page found at non-standard path",
                          "", "", ""});
    }
  }
  return findings;
}

/// Sensitive file via robots.txt.
std::vector<Finding> scan_robots_sensitive(const Config &, HttpClient &http,
                                            const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  auto resp = http.get(base + "/robots.txt");
  if (resp.status_code != 200) return findings;

  const std::vector<std::string> sensitive_keywords = {
      "admin", "backup", "config", "secret", "private",
      "internal", "staging", "api/v1", "debug", "test"};

  std::regex disallow_re(R"(Disallow:\s*(/[^\s]+))");
  auto it = std::sregex_iterator(resp.body.begin(), resp.body.end(), disallow_re);
  auto end = std::sregex_iterator();

  while (it != end) {
    std::string path = (*it)[1].str();
    for (const auto &kw : sensitive_keywords) {
      if (path.find(kw) != std::string::npos) {
        // Check if accessible
        auto check = http.get(base + path);
        if (check.status_code == 200 && check.body.size() > 100) {
          findings.push_back({"Sensitive Path in robots.txt", "low", base + path,
                              "robots.txt reveals and path is accessible: " + path,
                              "", "", ""});
          break;
        }
      }
    }
    ++it;
  }
  return findings;
}

/// Git exposure — check for .git/HEAD, .git/config.
std::vector<Finding> scan_git_exposure(const Config &, HttpClient &http,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  auto head = http.get(base + "/.git/HEAD");
  if (head.status_code == 200 && head.body.find("ref:") != std::string::npos) {
    findings.push_back({"Git Repository Exposed", "critical", base + "/.git/",
                        "Full source code recoverable via exposed .git directory",
                        "", "", "HEAD: " + head.body.substr(0, 50)});

    // Check config for credentials
    auto config = http.get(base + "/.git/config");
    if (config.status_code == 200 &&
        (config.body.find("password") != std::string::npos ||
         config.body.find("token") != std::string::npos)) {
      findings.push_back({"Git Config — Credentials", "critical", base + "/.git/config",
                          "Git config contains credentials/tokens",
                          "", "", config.body.substr(0, 200)});
    }
  }
  return findings;
}

/// SVN exposure.
std::vector<Finding> scan_svn_exposure(const Config &, HttpClient &http,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  auto resp = http.get(base + "/.svn/entries");
  if (resp.status_code == 200 && (resp.body.find("dir") != std::string::npos ||
                                    resp.body.find("svn") != std::string::npos)) {
    findings.push_back({"SVN Repository Exposed", "high", base + "/.svn/",
                        "SVN metadata accessible — source code disclosure",
                        "", "", resp.body.substr(0, 100)});
  }
  return findings;
}

/// Environment variable file.
std::vector<Finding> scan_env_file(const Config &, HttpClient &http,
                                    const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> env_paths = {
      "/.env", "/.env.production", "/.env.local", "/.env.staging",
      "/.env.development", "/.env.backup"};

  for (const auto &path : env_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 && resp.body.size() > 10 &&
        (resp.body.find("=") != std::string::npos) &&
        resp.body.find("<html") == std::string::npos) {
      // Verify it looks like an env file
      if (resp.body.find("DB_") != std::string::npos ||
          resp.body.find("API_") != std::string::npos ||
          resp.body.find("SECRET") != std::string::npos ||
          resp.body.find("KEY=") != std::string::npos) {
        findings.push_back({"Environment File Exposed: " + path, "critical", base + path,
                            "Env file with secrets publicly accessible",
                            "", "", resp.body.substr(0, 100) + "..."});
        break;
      }
    }
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_recon_advanced_scanners() {
  return {
      {"Internal IP Disclosure", scan_internal_ip},
      {"Staging Environment", scan_staging_env},
      {"K8s/Docker Exposed", scan_k8s_docker},
      {"CI/CD Config Leak", scan_cicd_leak},
      {"JS Library Vuln", scan_js_libraries},
      {"Email Security (SPF/DMARC)", scan_email_security},
      {"Exposed Metrics", scan_exposed_metrics},
      {"Hidden Admin Panel", scan_hidden_admin},
      {"Robots.txt Sensitive", scan_robots_sensitive},
      {"Git Exposure", scan_git_exposure},
      {"SVN Exposure", scan_svn_exposure},
      {"Env File Exposed", scan_env_file},
  };
}

} // namespace apex
