/// @file scanners/enterprise_osint.cpp
/// @brief Enterprise OSINT: Microsoft 365 tenant enum, Azure AD/Entra ID,
///        SharePoint exposure, Exchange autodiscover, Atlassian/Jira/Confluence,
///        Slack workspace discovery, OAuth app enumeration, cloud naming intel.
#include "scanner_base.hpp"
#include <set>

namespace apex {
namespace {

/// Microsoft 365 / Azure AD tenant enumeration and metadata.
std::vector<Finding> scan_m365_tenant(const Config &cfg, HttpClient &http,
                                      const CrawlResult &) {
  std::vector<Finding> findings;
  std::string domain = cfg.target;
  if (domain.find("://") != std::string::npos)
    domain = domain.substr(domain.find("://") + 3);
  if (domain.find('/') != std::string::npos)
    domain = domain.substr(0, domain.find('/'));

  // OpenID configuration — reveals tenant ID and auth endpoints.
  auto oidc = http.get("https://login.microsoftonline.com/" + domain +
                       "/.well-known/openid-configuration");
  if (oidc.status_code == 200 && oidc.body.find("tenant") != std::string::npos) {
    findings.push_back({"M365 Tenant Detected", "info", domain,
                        "Microsoft 365 / Azure AD tenant exists for this domain",
                        "", "", ""});

    // Extract tenant ID.
    std::regex tid_re(R"(([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}))");
    std::smatch m;
    if (std::regex_search(oidc.body, m, tid_re)) {
      findings.push_back({"Azure AD Tenant ID", "info", domain,
                          "Tenant ID: " + m[0].str(), "", "", ""});
    }
  }

  // GetUserRealm — reveals federation, auth type, cloud vs on-prem.
  auto realm = http.get("https://login.microsoftonline.com/getuserrealm.srf?login=user@" + domain);
  if (realm.status_code == 200) {
    if (realm.body.find("Federated") != std::string::npos) {
      findings.push_back({"M365 Federated Auth (ADFS/Okta)", "info", domain,
                          "Domain uses federated authentication — ADFS/Okta/PingFederate",
                          "", "", ""});
    } else if (realm.body.find("Managed") != std::string::npos) {
      findings.push_back({"M365 Managed Auth (Cloud)", "info", domain,
                          "Domain uses cloud-managed authentication", "", "", ""});
    }
    // Check for legacy auth hints.
    if (realm.body.find("NameSpaceType") != std::string::npos) {
      findings.push_back({"M365 Namespace Enumerable", "low", domain,
                          "GetUserRealm endpoint reveals auth configuration", "", "", ""});
    }
  }

  // Check for user enumeration via autodiscover.
  auto autodiscover = http.get("https://autodiscover." + domain + "/autodiscover/autodiscover.xml");
  if (autodiscover.status_code == 401) {
    findings.push_back({"Exchange Autodiscover Active", "info",
                        "autodiscover." + domain,
                        "Exchange autodiscover endpoint exists (401 = requires auth)",
                        "", "", ""});
  } else if (autodiscover.status_code == 200) {
    findings.push_back({"Exchange Autodiscover Open", "high",
                        "autodiscover." + domain,
                        "Autodiscover accessible without auth — config leak", "", "", ""});
  }

  return findings;
}

/// SharePoint / OneDrive exposure check.
std::vector<Finding> scan_sharepoint(const Config &cfg, HttpClient &http,
                                     const CrawlResult &) {
  std::vector<Finding> findings;
  std::string domain = cfg.target;
  if (domain.find("://") != std::string::npos)
    domain = domain.substr(domain.find("://") + 3);
  if (domain.find('/') != std::string::npos)
    domain = domain.substr(0, domain.find('/'));
  std::string org = domain.substr(0, domain.find('.'));

  // SharePoint tenant URLs.
  const std::vector<std::string> sp_urls = {
      "https://" + org + ".sharepoint.com",
      "https://" + org + "-my.sharepoint.com",
      "https://" + org + ".sharepoint.com/_api/web",
      "https://" + org + ".sharepoint.com/_api/search/query?querytext='*'",
      "https://" + org + ".sharepoint.com/sites/",
  };

  for (const auto &url : sp_urls) {
    auto resp = http.get(url);
    if (resp.status_code == 200 && resp.body.size() > 100) {
      findings.push_back({"SharePoint Accessible", "medium", url,
                          "SharePoint endpoint accessible — check guest/anonymous access",
                          "", "", ""});
    } else if (resp.status_code == 403) {
      findings.push_back({"SharePoint Exists", "info", url,
                          "SharePoint tenant exists (403 = auth required)", "", "", ""});
    }
  }

  // Common public SharePoint sites.
  for (const auto &site : {"public", "intranet", "hr", "wiki", "docs", "portal"}) {
    auto resp = http.get("https://" + org + ".sharepoint.com/sites/" + site);
    if (resp.status_code == 200 && resp.body.size() > 500) {
      findings.push_back({"SharePoint Site Public: " + std::string(site), "high",
                          "https://" + org + ".sharepoint.com/sites/" + site,
                          "SharePoint site '" + std::string(site) + "' publicly accessible",
                          "", "", ""});
    }
  }
  return findings;
}

/// Atlassian (Jira/Confluence) exposure.
std::vector<Finding> scan_atlassian(const Config &cfg, HttpClient &http,
                                    const CrawlResult &) {
  std::vector<Finding> findings;
  std::string domain = cfg.target;
  if (domain.find("://") != std::string::npos)
    domain = domain.substr(domain.find("://") + 3);
  if (domain.find('/') != std::string::npos)
    domain = domain.substr(0, domain.find('/'));
  std::string org = domain.substr(0, domain.find('.'));

  // Atlassian cloud instances.
  struct AtlassianCheck { std::string url; std::string name; };
  std::vector<AtlassianCheck> checks = {
      {"https://" + org + ".atlassian.net", "Atlassian Cloud"},
      {"https://" + org + ".atlassian.net/rest/api/2/serverInfo", "Jira API"},
      {"https://" + org + ".atlassian.net/wiki/rest/api/space", "Confluence Spaces"},
      {"https://" + org + ".atlassian.net/rest/api/2/user/search?query=a", "Jira User Enum"},
      {"https://jira." + domain, "Self-hosted Jira"},
      {"https://confluence." + domain, "Self-hosted Confluence"},
  };

  for (const auto &check : checks) {
    auto resp = http.get(check.url);
    if (resp.status_code == 200 && resp.body.size() > 50) {
      std::string severity = "info";
      if (resp.body.find("displayName") != std::string::npos ||
          resp.body.find("emailAddress") != std::string::npos)
        severity = "high";
      else if (resp.body.find("key") != std::string::npos)
        severity = "medium";
      findings.push_back({check.name + " Exposed", severity, check.url,
                          check.name + " accessible — may leak project/user info",
                          "", "", ""});
    }
  }
  return findings;
}

/// Slack workspace discovery.
std::vector<Finding> scan_slack(const Config &cfg, HttpClient &http,
                                const CrawlResult &crawl) {
  std::vector<Finding> findings;
  std::string domain = cfg.target;
  if (domain.find("://") != std::string::npos)
    domain = domain.substr(domain.find("://") + 3);
  if (domain.find('/') != std::string::npos)
    domain = domain.substr(0, domain.find('/'));
  std::string org = domain.substr(0, domain.find('.'));

  // Check Slack workspace.
  auto resp = http.get("https://" + org + ".slack.com");
  if (resp.status_code == 200 && resp.body.find("slack") != std::string::npos) {
    findings.push_back({"Slack Workspace Found", "info", "https://" + org + ".slack.com",
                        "Slack workspace exists for this organization", "", "", ""});
  }

  // Check for leaked Slack webhooks in source.
  for (const auto &url : crawl.urls) {
    auto page = http.get(url);
    if (page.body.find("hooks.slack.com") != std::string::npos) {
      findings.push_back({"Slack Webhook Leaked", "high", url,
                          "Slack webhook URL in source — can post messages to channels",
                          "", "", ""});
      break;
    }
  }
  return findings;
}

/// OAuth / SSO enumeration — discover identity providers and apps.
std::vector<Finding> scan_oauth_enum(const Config &cfg, HttpClient &http,
                                     const CrawlResult &crawl) {
  std::vector<Finding> findings;
  std::string domain = cfg.target;
  if (domain.find("://") != std::string::npos)
    domain = domain.substr(domain.find("://") + 3);
  if (domain.find('/') != std::string::npos)
    domain = domain.substr(0, domain.find('/'));
  std::string org = domain.substr(0, domain.find('.'));

  // Check common SSO/IdP endpoints.
  struct SSOCheck { std::string url; std::string provider; };
  std::vector<SSOCheck> checks = {
      {"https://" + org + ".okta.com", "Okta"},
      {"https://sso." + domain, "SSO Portal"},
      {"https://login." + domain, "Login Portal"},
      {"https://auth." + domain, "Auth Portal"},
      {"https://" + org + ".auth0.com", "Auth0"},
      {"https://accounts.google.com/o/saml2?idpid=" + org, "Google SAML"},
  };

  for (const auto &check : checks) {
    auto resp = http.get(check.url);
    if (resp.status_code == 200 || resp.status_code == 302) {
      findings.push_back({check.provider + " Detected", "info", check.url,
                          check.provider + " identity provider in use", "", "", ""});
    }
  }

  // Check for OAuth consent phishing vectors — overly permissive app registrations.
  if (!crawl.urls.empty()) {
    std::string base = base_url_from(crawl.urls[0]);
    auto resp = http.get(base + "/.well-known/openid-configuration");
    if (resp.status_code == 200 && resp.body.find("authorization_endpoint") != std::string::npos) {
      findings.push_back({"OpenID Configuration Exposed", "info", base + "/.well-known/openid-configuration",
                          "OpenID Connect configuration available", "", "", ""});
    }
  }
  return findings;
}

/// Cloud resource naming intelligence.
std::vector<Finding> scan_cloud_naming(const Config &cfg, HttpClient &http,
                                       const CrawlResult &) {
  std::vector<Finding> findings;
  std::string domain = cfg.target;
  if (domain.find("://") != std::string::npos)
    domain = domain.substr(domain.find("://") + 3);
  if (domain.find('/') != std::string::npos)
    domain = domain.substr(0, domain.find('/'));
  std::string org = domain.substr(0, domain.find('.'));

  // Enumerate cloud resources by naming convention.
  struct CloudResource { std::string url; std::string type; };
  std::vector<CloudResource> resources = {
      // Azure
      {"https://" + org + ".azurewebsites.net", "Azure App Service"},
      {"https://" + org + "-dev.azurewebsites.net", "Azure App Service (dev)"},
      {"https://" + org + "-staging.azurewebsites.net", "Azure App Service (staging)"},
      {"https://" + org + ".database.windows.net", "Azure SQL"},
      {"https://" + org + ".vault.azure.net", "Azure Key Vault"},
      {"https://" + org + ".azurecr.io", "Azure Container Registry"},
      // AWS
      {"https://" + org + ".s3.amazonaws.com", "AWS S3"},
      {"https://" + org + "-prod.s3.amazonaws.com", "AWS S3 (prod)"},
      {"https://" + org + ".execute-api.us-east-1.amazonaws.com", "AWS API Gateway"},
      // GCP
      {"https://" + org + ".appspot.com", "GCP App Engine"},
      {"https://" + org + "-prod.appspot.com", "GCP App Engine (prod)"},
      {"https://" + org + ".cloudfunctions.net", "GCP Cloud Functions"},
      // Heroku/Render
      {"https://" + org + ".herokuapp.com", "Heroku"},
      {"https://" + org + ".onrender.com", "Render"},
  };

  for (const auto &res : resources) {
    auto resp = http.get(res.url);
    if (resp.status_code > 0 && resp.status_code < 500 && resp.error.empty()) {
      findings.push_back({"Cloud Resource: " + res.type, "info", res.url,
                          res.type + " exists — reveals infrastructure naming",
                          "", "", ""});
    }
  }
  return findings;
}

/// User enumeration via common SaaS login flows.
std::vector<Finding> scan_user_enum(const Config &cfg, HttpClient &http,
                                    const CrawlResult &) {
  std::vector<Finding> findings;
  std::string domain = cfg.target;
  if (domain.find("://") != std::string::npos)
    domain = domain.substr(domain.find("://") + 3);
  if (domain.find('/') != std::string::npos)
    domain = domain.substr(0, domain.find('/'));

  // Microsoft user enumeration via GetCredentialType.
  auto resp = http.post("https://login.microsoftonline.com/common/GetCredentialType",
                        R"({"Username":"nonexistent_user_xyz@)" + domain + R"("})",
                        "application/json");
  if (resp.status_code == 200) {
    // If IfExistsResult == 0, user exists; 1 = doesn't exist.
    // If both return same response, enumeration is not possible.
    auto resp2 = http.post("https://login.microsoftonline.com/common/GetCredentialType",
                           R"({"Username":"admin@)" + domain + R"("})",
                           "application/json");
    if (resp.body != resp2.body) {
      findings.push_back({"M365 User Enumeration", "medium", domain,
                          "Microsoft login reveals whether accounts exist — aids password spraying",
                          "", "", ""});
    }
  }

  return findings;
}

} // namespace

std::vector<Scanner> register_enterprise_osint_scanners() {
  return {
      {"M365 Tenant Enum", scan_m365_tenant},
      {"SharePoint Exposure", scan_sharepoint},
      {"Atlassian (Jira/Confluence)", scan_atlassian},
      {"Slack Discovery", scan_slack},
      {"OAuth/SSO Enum", scan_oauth_enum},
      {"Cloud Naming Intel", scan_cloud_naming},
      {"User Enumeration", scan_user_enum},
  };
}

} // namespace apex
