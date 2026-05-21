/// @file scanners/cms_misconfig.cpp
/// @brief CMS misconfiguration scanner: checks for exposed admin panels,
///        debug mode, default credentials, open GraphQL, backup files,
///        plugin vulnerabilities, and platform-specific misconfigs.
#include "scanner_base.hpp"

namespace apex {
namespace {

/// Check for exposed admin panels.
std::vector<Finding> scan_cms_admin_exposure(const Config &, HttpClient &http,
                                            const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::pair<std::string, std::string>> panels = {
      {"/wp-admin/", "WordPress"},
      {"/wp-login.php", "WordPress"},
      {"/administrator/", "Joomla"},
      {"/admin/", "Generic"},
      {"/user/login", "Drupal"},
      {"/typo3/", "TYPO3"},
      {"/umbraco/", "Umbraco"},
      {"/sitecore/login", "Sitecore"},
      {"/phpmyadmin/", "phpMyAdmin"},
      {"/adminer.php", "Adminer"},
      {"/crx/de", "AEM"},
      {"/ghost/", "Ghost"},
      {"/cockpit/", "Cockpit CMS"},
      {"/directus/", "Directus"},
      {"/strapi/", "Strapi"},
      {"/admin/config.yml", "Netlify/Decap CMS"},
      {"/_layouts/15/start.aspx", "SharePoint"},
      {"/magnoliaAuthor/", "Magnolia"},
      {"/cms/", "Jahia/Bloomreach"},
      {"/wps/portal", "HCL DX"},
  };

  for (const auto &[path, cms] : panels) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 && resp.body.size() > 200 &&
        resp.body.find("404") == std::string::npos) {
      findings.push_back({"CMS Admin Exposed", "high", base + path,
                          cms + " admin panel accessible from internet",
                          "", "", ""});
    }
  }
  return findings;
}

/// Check for debug/dev mode indicators.
std::vector<Finding> scan_cms_debug_mode(const Config &, HttpClient &http,
                                         const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::pair<std::string, std::string>> debug_paths = {
      {"/debug/", "Debug endpoint"},
      {"/_debug/", "Debug endpoint"},
      {"/app_dev.php", "Symfony dev mode"},
      {"/info.php", "PHP info"},
      {"/phpinfo.php", "PHP info"},
      {"/elmah.axd", ".NET error log"},
      {"/trace.axd", ".NET trace"},
      {"/actuator/env", "Spring Actuator env"},
      {"/actuator/heapdump", "Spring Actuator heap"},
      {"/__debug__/", "Django debug toolbar"},
      {"/_profiler/", "Symfony profiler"},
      {"/server-status", "Apache status"},
      {"/server-info", "Apache info"},
      {"/nginx_status", "Nginx status"},
  };

  for (const auto &[path, desc] : debug_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 && resp.body.size() > 100) {
      findings.push_back({"Debug Mode Exposed", "high", base + path,
                          desc + " accessible in production", "", "", ""});
    }
  }

  // Check main page for debug indicators.
  auto home = http.get(base + "/");
  const std::vector<std::string> debug_sigs = {
      "Traceback (most recent", "DJANGO_SETTINGS_MODULE",
      "joomla-debug", "system-debug", "Xdebug",
      "APP_DEBUG=true", "WP_DEBUG"};
  for (const auto &sig : debug_sigs) {
    if (home.body.find(sig) != std::string::npos) {
      findings.push_back({"Debug Mode Active", "high", base,
                          "Debug indicator found: " + sig, "", "", ""});
      break;
    }
  }
  return findings;
}

/// Check for open GraphQL introspection.
std::vector<Finding> scan_graphql_introspection(const Config &, HttpClient &http,
                                                const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> gql_paths = {
      "/graphql", "/graphql/", "/api/graphql", "/v1/graphql",
      "/gql", "/query", "/graphiql"};
  const std::string introspection =
      R"({"query":"{ __schema { types { name } } }"})";

  for (const auto &path : gql_paths) {
    auto resp = http.post(base + path, introspection, "application/json");
    if (resp.status_code == 200 && resp.body.find("__schema") != std::string::npos) {
      findings.push_back({"GraphQL Introspection", "medium", base + path,
                          "GraphQL introspection enabled — full schema exposed",
                          "", "", ""});
      break;
    }
  }
  return findings;
}

/// Check for default credentials on common platforms.
std::vector<Finding> scan_default_creds(const Config &, HttpClient &http,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  struct DefaultCred {
    const char *path;
    const char *post_data;
    const char *content_type;
    const char *success_indicator;
    const char *platform;
  };
  const DefaultCred creds[] = {
      {"/phpmyadmin/index.php", "pma_username=root&pma_password=",
       "application/x-www-form-urlencoded", "server_databases", "phpMyAdmin (root/empty)"},
      {"/api/login", R"({"username":"admin","password":"admin"})",
       "application/json", "token", "API (admin/admin)"},
      {"/api/login", R"({"username":"admin","password":"password"})",
       "application/json", "token", "API (admin/password)"},
  };

  for (const auto &c : creds) {
    auto resp = http.post(base + c.path, c.post_data, c.content_type);
    if (resp.status_code == 200 &&
        resp.body.find(c.success_indicator) != std::string::npos) {
      findings.push_back({"Default Credentials", "critical", base + c.path,
                          std::string(c.platform) + " — default creds work",
                          "", "", ""});
    }
  }
  return findings;
}

/// WordPress-specific misconfiguration checks.
std::vector<Finding> scan_wp_misconfig(const Config &, HttpClient &http,
                                       const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Check if it's WordPress first.
  auto home = http.get(base + "/");
  if (home.body.find("wp-content") == std::string::npos) return findings;

  // xmlrpc.php
  auto xmlrpc = http.post(base + "/xmlrpc.php",
      "<?xml version=\"1.0\"?><methodCall><methodName>system.listMethods</methodName></methodCall>",
      "text/xml");
  if (xmlrpc.body.find("wp.getUsersBlogs") != std::string::npos)
    findings.push_back({"WP xmlrpc.php", "medium", base + "/xmlrpc.php",
                        "xmlrpc.php enabled — brute-force & DDoS vector", "", "", ""});

  // User enumeration
  auto users = http.get(base + "/wp-json/wp/v2/users");
  if (users.status_code == 200 && users.body.find("\"slug\"") != std::string::npos)
    findings.push_back({"WP User Enum", "medium", base + "/wp-json/wp/v2/users",
                        "User enumeration via REST API", "", "", ""});

  // wp-config.php backup
  const std::vector<std::string> config_paths = {
      "/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.old",
      "/wp-config.php.swp", "/wp-config.txt"};
  for (const auto &p : config_paths) {
    auto resp = http.get(base + p);
    if (resp.status_code == 200 && resp.body.find("DB_PASSWORD") != std::string::npos) {
      findings.push_back({"WP Config Leak", "critical", base + p,
                          "wp-config backup with DB credentials exposed", "", "", ""});
      break;
    }
  }

  // Debug log
  auto debug_log = http.get(base + "/wp-content/debug.log");
  if (debug_log.status_code == 200 && debug_log.body.size() > 50)
    findings.push_back({"WP Debug Log", "medium", base + "/wp-content/debug.log",
                        "WordPress debug.log publicly accessible", "", "", ""});

  // Uploads directory listing
  auto uploads = http.get(base + "/wp-content/uploads/");
  if (uploads.body.find("Index of") != std::string::npos)
    findings.push_back({"WP Uploads Listing", "medium", base + "/wp-content/uploads/",
                        "Directory listing on uploads folder", "", "", ""});

  return findings;
}

/// Joomla/Drupal/Magento specific misconfigs.
std::vector<Finding> scan_platform_misconfig(const Config &, HttpClient &http,
                                             const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);
  auto home = http.get(base + "/");

  // Joomla
  if (home.body.find("Joomla") != std::string::npos ||
      home.body.find("/administrator/") != std::string::npos) {
    auto cfg = http.get(base + "/configuration.php.bak");
    if (cfg.status_code == 200 && cfg.body.find("$host") != std::string::npos)
      findings.push_back({"Joomla Config Leak", "critical", base + "/configuration.php.bak",
                          "Joomla config backup with DB creds", "", "", ""});
  }

  // Drupal
  if (home.body.find("Drupal") != std::string::npos) {
    auto changelog = http.get(base + "/CHANGELOG.txt");
    if (changelog.status_code == 200 && changelog.body.find("Drupal") != std::string::npos)
      findings.push_back({"Drupal Version Leak", "low", base + "/CHANGELOG.txt",
                          "Drupal CHANGELOG.txt exposes exact version", "", "", ""});
  }

  // Magento
  if (home.body.find("Mage") != std::string::npos) {
    auto downloader = http.get(base + "/downloader/");
    if (downloader.status_code == 200 && downloader.body.find("Magento") != std::string::npos)
      findings.push_back({"Magento Downloader", "high", base + "/downloader/",
                          "Magento Connect Manager exposed", "", "", ""});
  }

  // AEM
  auto crx = http.get(base + "/crx/packmgr/index.jsp");
  if (crx.status_code == 200 && crx.body.find("Package Manager") != std::string::npos)
    findings.push_back({"AEM Package Manager", "critical", base + "/crx/packmgr/index.jsp",
                        "AEM CRX Package Manager exposed — RCE possible", "", "", ""});

  auto aem_users = http.get(base + "/bin/querybuilder.json?path=/home/users&p.limit=-1");
  if (aem_users.status_code == 200 && aem_users.body.find("rep:User") != std::string::npos)
    findings.push_back({"AEM User Enum", "high", base,
                        "AEM QueryBuilder exposes user list", "", "", ""});

  return findings;
}

} // namespace

std::vector<Scanner> register_cms_misconfig_scanners() {
  return {
      {"CMS Admin Exposure", scan_cms_admin_exposure},
      {"CMS Debug Mode", scan_cms_debug_mode},
      {"GraphQL Introspection", scan_graphql_introspection},
      {"Default Credentials", scan_default_creds},
      {"WordPress Misconfig", scan_wp_misconfig},
      {"Platform Misconfig", scan_platform_misconfig},
  };
}

} // namespace apex
