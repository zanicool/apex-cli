/// @file scanners/supply_chain.cpp
/// @brief Supply chain scan: detect exposed cloud resources, self-hosted tools,
///        misconfigured integrations from common MKB IT suppliers.
#include "scanner_base.hpp"
#include <set>

namespace apex {
namespace {

/// Detect exposed self-hosted tools (GitLab, Synology, QNAP, etc).
std::vector<Finding> scan_self_hosted_tools(const Config &, HttpClient &http,
                                            const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);
  size_t start = base.find("://") + 3;
  std::string domain = base.substr(start);

  struct Tool {
    const char *subdomain;
    const char *path;
    const char *fingerprint;
    const char *name;
    const char *severity;
  };
  const Tool tools[] = {
      {"gitlab", "/users/sign_in", "GitLab", "GitLab", "medium"},
      {"git", "/users/sign_in", "GitLab", "GitLab", "medium"},
      {"jenkins", "/login", "Jenkins", "Jenkins", "high"},
      {"ci", "/login", "Jenkins", "Jenkins CI", "high"},
      {"nas", "/", "Synology", "Synology NAS", "high"},
      {"nas", "/cgi-bin/", "QNAP", "QNAP NAS", "high"},
      {"portainer", "/", "Portainer", "Portainer (Docker)", "high"},
      {"grafana", "/login", "Grafana", "Grafana", "medium"},
      {"monitor", "/", "Zabbix", "Zabbix", "medium"},
      {"vpn", "/", "OpenVPN", "OpenVPN", "medium"},
      {"mail", "/", "Roundcube", "Roundcube Webmail", "low"},
      {"webmail", "/", "Roundcube", "Webmail", "low"},
      {"erp", "/", "Odoo", "Odoo ERP", "medium"},
      {"crm", "/", "login", "CRM System", "low"},
      {"backup", "/", "Veeam", "Veeam Backup", "high"},
  };

  for (const auto &t : tools) {
    std::string url = "https://" + std::string(t.subdomain) + "." + domain + t.path;
    auto resp = http.get(url);
    if (resp.status_code == 200 &&
        resp.body.find(t.fingerprint) != std::string::npos) {
      findings.push_back({"Supply Chain: Self-Hosted", t.severity, url,
                          std::string(t.name) + " exposed on subdomain",
                          "", "", ""});
    }
  }
  return findings;
}

/// Detect exposed cloud storage (S3, Azure Blob, GCS) linked to target.
std::vector<Finding> scan_cloud_storage_exposure(const Config &, HttpClient &http,
                                                 const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);
  size_t start = base.find("://") + 3;
  std::string domain = base.substr(start);
  size_t dot = domain.find('.');
  std::string org = (dot != std::string::npos) ? domain.substr(0, dot) : domain;

  // S3 bucket patterns.
  const std::vector<std::string> s3_suffixes = {
      "", "-backup", "-assets", "-uploads", "-data", "-dev", "-staging",
      "-prod", "-media", "-logs", "-private", "-internal", "-db"};
  for (const auto &suffix : s3_suffixes) {
    std::string bucket = org + suffix;
    auto resp = http.get("https://" + bucket + ".s3.amazonaws.com/");
    if (resp.status_code == 200 &&
        resp.body.find("<ListBucketResult") != std::string::npos) {
      findings.push_back({"Supply Chain: S3 Public", "critical",
                          "https://" + bucket + ".s3.amazonaws.com/",
                          "Public S3 bucket listing: " + bucket, "", "", ""});
    }
  }

  // Azure Blob patterns.
  for (const auto &suffix : s3_suffixes) {
    std::string container = org + suffix;
    std::string url = "https://" + org + ".blob.core.windows.net/" +
                      container + "?restype=container&comp=list";
    auto resp = http.get(url);
    if (resp.status_code == 200 &&
        resp.body.find("<EnumerationResults") != std::string::npos) {
      findings.push_back({"Supply Chain: Azure Blob Public", "critical", url,
                          "Public Azure Blob container: " + container,
                          "", "", ""});
    }
  }

  // GCS patterns.
  auto gcs = http.get("https://storage.googleapis.com/" + org + "/");
  if (gcs.status_code == 200 && gcs.body.find("<ListBucket") != std::string::npos) {
    findings.push_back({"Supply Chain: GCS Public", "critical",
                        "https://storage.googleapis.com/" + org + "/",
                        "Public GCS bucket: " + org, "", "", ""});
  }
  return findings;
}

/// Detect third-party integrations leaking data (analytics, error tracking).
std::vector<Finding> scan_integration_leaks(const Config &, HttpClient &http,
                                            const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  auto resp = http.get(crawl.urls[0]);
  if (resp.status_code != 200) return findings;

  struct Integration {
    const char *pattern;
    const char *name;
    const char *risk;
  };
  const Integration integrations[] = {
      {"sentry.io", "Sentry", "Error tracking may expose stack traces"},
      {"hotjar.com", "Hotjar", "Session recording captures user input"},
      {"fullstory.com", "FullStory", "Session replay captures sensitive data"},
      {"logrocket.com", "LogRocket", "Session replay active"},
      {"intercom.io", "Intercom", "Chat widget may expose internal info"},
      {"crisp.chat", "Crisp", "Chat widget active"},
      {"hubspot.com", "HubSpot", "Marketing tracking active"},
      {"segment.io", "Segment", "Analytics pipeline active"},
      {"mixpanel.com", "Mixpanel", "User analytics tracking"},
      {"firebase", "Firebase", "Firebase integration (check rules)"},
  };

  for (const auto &i : integrations) {
    if (resp.body.find(i.pattern) != std::string::npos) {
      findings.push_back({"Supply Chain: Integration", "info", crawl.urls[0],
                          std::string(i.name) + " — " + i.risk, "", "", ""});
    }
  }
  return findings;
}

/// Detect exposed management panels from common MKB suppliers.
std::vector<Finding> scan_management_panels(const Config &, HttpClient &http,
                                            const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  struct Panel {
    const char *path;
    const char *fingerprint;
    const char *name;
  };
  const Panel panels[] = {
      {":8443/", "UniFi", "Ubiquiti UniFi Controller"},
      {":8080/", "RouterOS", "MikroTik RouterOS"},
      {":2083/", "cPanel", "cPanel"},
      {":8006/", "Proxmox", "Proxmox VE"},
      {":9090/", "Cockpit", "Cockpit Server Manager"},
      {":3000/", "Grafana", "Grafana"},
      {":5000/", "Synology", "Synology DSM"},
      {":8081/", "Portainer", "Portainer"},
      {":9000/", "Portainer", "Portainer"},
      {":10000/", "Webmin", "Webmin"},
  };

  size_t start = base.find("://") + 3;
  std::string host = base.substr(start);

  for (const auto &p : panels) {
    std::string url = "https://" + host + p.path;
    auto resp = http.get(url);
    if (resp.status_code == 200 &&
        resp.body.find(p.fingerprint) != std::string::npos) {
      findings.push_back({"Supply Chain: Management Panel", "high", url,
                          std::string(p.name) + " exposed", "", "", ""});
    }
  }
  return findings;
}

/// Detect MFA/SSO configuration issues on login pages.
std::vector<Finding> scan_sso_misconfig(const Config &, HttpClient &http,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Check if SSO/OAuth login is available but also allows password fallback.
  auto resp = http.get(base + "/");
  bool has_sso = resp.body.find("oauth") != std::string::npos ||
                 resp.body.find("saml") != std::string::npos ||
                 resp.body.find("Sign in with") != std::string::npos ||
                 resp.body.find("Microsoft") != std::string::npos;
  bool has_password = resp.body.find("password") != std::string::npos &&
                      resp.body.find("type=\"password\"") != std::string::npos;

  if (has_sso && has_password) {
    findings.push_back({"Supply Chain: SSO Bypass", "medium", base,
                        "SSO available but password login not disabled",
                        "", "", ""});
  }
  return findings;
}

/// Detect exposed API keys/tokens from third-party services in page source.
std::vector<Finding> scan_exposed_api_keys(const Config &, HttpClient &http,
                                           const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  for (const auto &url : crawl.urls) {
    auto resp = http.get(url);
    if (resp.status_code != 200) continue;

    struct KeyPattern {
      const char *pattern;
      const char *service;
    };
    const KeyPattern patterns[] = {
        {"AIza", "Google API Key"},
        {"AKIA", "AWS Access Key"},
        {"sk_live_", "Stripe Live Key"},
        {"pk_live_", "Stripe Publishable Key"},
        {"xoxb-", "Slack Bot Token"},
        {"ghp_", "GitHub Personal Token"},
        {"glpat-", "GitLab Personal Token"},
        {"sq0csp-", "Square OAuth Secret"},
        {"SG.", "SendGrid API Key"},
    };

    for (const auto &kp : patterns) {
      if (resp.body.find(kp.pattern) != std::string::npos) {
        findings.push_back({"Supply Chain: API Key Exposed", "critical", url,
                            std::string(kp.service) + " key found in source",
                            "", kp.pattern, ""});
      }
    }
    break; // Check first page only.
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_supply_chain_scanners() {
  return {
      {"Supply Chain: Self-Hosted Tools", scan_self_hosted_tools},
      {"Supply Chain: Cloud Storage", scan_cloud_storage_exposure},
      {"Supply Chain: Integrations", scan_integration_leaks},
      {"Supply Chain: Management Panels", scan_management_panels},
      {"Supply Chain: SSO Config", scan_sso_misconfig},
      {"Supply Chain: API Keys", scan_exposed_api_keys},
  };
}

} // namespace apex
