#include <string>
#include <vector>

#include "scanner_base.hpp"

namespace apex {

std::vector<Scanner> register_wordpress_deep_scanners() {
  return {
      {"WP REST API Sensitive Endpoints",
       [](const Config& cfg, HttpClient& http, const CrawlResult& crawl) -> std::vector<Finding> {
         std::vector<Finding> findings;
         std::vector<std::string> bases;
         for (const auto& u : crawl.urls) {
           auto pos = u.find("/", 8);
           if (pos != std::string::npos) bases.push_back(u.substr(0, pos));
         }
         if (bases.empty()) bases.push_back("https://" + cfg.target);

         // Sensitive WP REST endpoints that should require auth
         std::vector<std::pair<std::string, std::string>> endpoints = {
             {"/wp-json/wc/v3/orders", "WooCommerce orders"},
             {"/wp-json/wc/v3/customers", "WooCommerce customers"},
             {"/wp-json/wc/v3/wc_stripe/settings", "Stripe settings"},
             {"/wp-json/wc-admin/options?options=woocommerce_stripe_settings", "Stripe config"},
             {"/wp-json/wp/v2/settings", "WP settings"},
             {"/wp-json/wp/v2/users?context=edit", "User details (edit context)"},
             {"/wp-json/redirection/v1/setting", "Redirection settings"},
             {"/wp-json/jetpack/v4/module/all", "Jetpack modules"},
             {"/wp-json/yoast/v1/configuration/site_representation", "Yoast config"},
             {"/wp-json/wpe_sign_on_plugin/v1/is_user_logged_in", "WPE auth status"},
             {"/wp-json/wp/v2/search?search=password&subtype=post&per_page=100", "Password in posts"},
             {"/wp-json/wc/v3/payment_gateways", "Payment gateways"},
             {"/wp-json/wc/v3/system_status", "System status"},
             {"/wp-json/wp/v2/themes", "Installed themes"},
             {"/wp-json/wp/v2/plugins", "Installed plugins"},
         };

         for (const auto& base : bases) {
           for (const auto& [ep, desc] : endpoints) {
             auto resp = http.get(base + ep);
             if (resp.status_code == 200 && resp.body.size() > 50 && resp.body.find("\"code\"") == std::string::npos) {
               // Check if it contains sensitive data
               bool sensitive = resp.body.find("email") != std::string::npos || resp.body.find("secret") != std::string::npos ||
                                resp.body.find("key") != std::string::npos || resp.body.find("password") != std::string::npos ||
                                resp.body.find("token") != std::string::npos || resp.body.find("customer") != std::string::npos;
               if (sensitive) {
                 findings.push_back({"WP REST API Data Exposure: " + desc, "high", base + ep, "", "", resp.body.substr(0, 100), ""});
               }
             }
           }
         }
         return findings;
       }},

      {"WP Plugin Vulnerability Check",
       [](const Config& cfg, HttpClient& http, const CrawlResult& crawl) -> std::vector<Finding> {
         std::vector<Finding> findings;
         std::string base = crawl.urls.empty() ? "https://" + cfg.target : crawl.urls[0].substr(0, crawl.urls[0].find("/", 8));

         // Check for known vulnerable plugin paths
         std::vector<std::pair<std::string, std::string>> plugin_checks = {
             {"/wp-content/plugins/wp-file-manager/readme.txt", "WP File Manager (CVE-2020-25213)"},
             {"/wp-content/plugins/elementor/readme.txt", "Elementor"},
             {"/wp-content/plugins/contact-form-7/readme.txt", "Contact Form 7"},
             {"/wp-content/plugins/woocommerce/readme.txt", "WooCommerce"},
             {"/wp-content/debug.log", "Debug log exposed"},
             {"/wp-config.php.bak", "Config backup"},
             {"/wp-config.php~", "Config backup (vim)"},
             {"/.wp-config.php.swp", "Config swap file"},
             {"/wp-content/uploads/wc-logs/", "WooCommerce logs"},
             {"/wp-content/uploads/gravity_forms/", "Gravity Forms uploads"},
             {"/wp-content/backups-dup-lite/", "Duplicator backups"},
         };

         for (const auto& [path, desc] : plugin_checks) {
           auto resp = http.get(base + path);
           if (resp.status_code == 200 && resp.body.size() > 50) {
             std::string sev = "medium";
             if (path.find("debug.log") != std::string::npos || path.find("config") != std::string::npos ||
                 path.find("backups") != std::string::npos)
               sev = "high";
             findings.push_back({"WP Sensitive File: " + desc, sev, base + path, "", "", resp.body.substr(0, 100), ""});
           }
         }
         return findings;
       }},

      {"WP SSRF via Webhooks",
       [](const Config& cfg, HttpClient& http, const CrawlResult& crawl) -> std::vector<Finding> {
         std::vector<Finding> findings;
         std::string base = crawl.urls.empty() ? "https://" + cfg.target : crawl.urls[0].substr(0, crawl.urls[0].find("/", 8));

         // Test SSRF via WooCommerce webhooks and other URL-accepting endpoints
         std::vector<std::string> ssrf_endpoints = {
             "/wp-json/wc/v3/webhooks",
             "/wp-json/wp/v2/media?source_url=http://169.254.169.254/latest/meta-data/",
         };

         for (const auto& ep : ssrf_endpoints) {
           auto resp = http.get(base + ep);
           if (resp.status_code == 200 &&
               (resp.body.find("ami-id") != std::string::npos || resp.body.find("instance-id") != std::string::npos)) {
             findings.push_back({"SSRF via WordPress endpoint", "critical", base + ep, "", "", resp.body.substr(0, 100), ""});
           }
         }
         return findings;
       }},
  };
}

}  // namespace apex
