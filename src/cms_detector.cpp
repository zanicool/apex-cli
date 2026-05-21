#include "cms_detector.hpp"
#include "config.hpp"
#include "http.hpp"
#include <algorithm>

CMSDetector::CMSDetector() {
    init_fingerprints();
}

void CMSDetector::init_fingerprints() {
    fingerprints = {
        {"WordPress", {"/wp-admin/", "/wp-content/"}, {}, {"wp-content"}, 
         "/wp-includes/version.php", "wp_version.*?([0-9.]+)", "6.5.3"},
        {"Drupal", {"/misc/drupal.js"}, {"X-Generator"}, {"Drupal.settings"}, 
         "/core/lib/Drupal.php", "VERSION = '([0-9.]+)'", "10.2.6"},
        {"Joomla", {"/administrator/"}, {}, {"Joomla!"}, 
         "/administrator/manifests/files/joomla.xml", "<version>([0-9.]+)</version>", "5.1.0"},
        {"Magento", {"/skin/frontend/"}, {}, {"Mage.Cookies"}, 
         "/js/mage/cookies.js", "Magento.*?([0-9.]+)", "2.4.7"},
        {"Ghost", {"/ghost/"}, {"X-Powered-By"}, {"ghost-"}, 
         "/ghost/api/", "version.*?([0-9.]+)", "5.82.0"},
        {"TYPO3", {"/typo3/"}, {"X-TYPO3-Parsetime"}, {"TYPO3"}, 
         "/typo3/", "VERSION = '([0-9.]+)'", "13.1.0"},
        {"Craft CMS", {"/cpresources/"}, {"X-Powered-By"}, {"Craft."}, 
         "/", "Craft CMS ([0-9.]+)", "5.1.0"},
        {"PrestaShop", {"/modules/"}, {}, {"prestashop"}, 
         "/config/settings.inc.php", "_PS_VERSION_.*?'([0-9.]+)'", "8.1.5"},
        {"OpenCart", {"/catalog/"}, {}, {"catalog/view/javascript"}, 
         "/admin/index.php", "OpenCart ([0-9.]+)", "4.0.2.3"},
        {"WooCommerce", {"/wp-content/plugins/woocommerce/"}, {}, {"woocommerce"}, 
         "/wp-content/plugins/woocommerce/readme.txt", "Stable tag: ([0-9.]+)", "8.8.3"},
        {"Strapi", {"/admin"}, {"X-Powered-By"}, {"strapi"}, 
         "/admin/", "strapi.*?([0-9.]+)", "4.22.0"},
        {"Umbraco", {"/umbraco/"}, {"X-Umbraco-Version"}, {"Umbraco"}, 
         "/", "X-Umbraco-Version: ([0-9.]+)", "13.3.0"},
        {"Sitecore", {"/sitecore/"}, {}, {"Sitecore"}, 
         "/sitecore/shell/sitecore.version.xml", "<version>([0-9.]+)</version>", "10.3.1"},
        {"Shopify", {}, {"X-ShopId"}, {"cdn.shopify.com"}, "/", "", "N/A"},
        {"Wix", {}, {"X-Wix-Request-Id"}, {"wix.com"}, "/", "", "N/A"},
        {"Squarespace", {}, {"X-Squarespace-Renderer"}, {"squarespace.com"}, "/", "", "N/A"},
        {"Webflow", {}, {}, {"webflow.io"}, "/", "", "N/A"},
        {"Contentful", {}, {}, {"contentful.com"}, "/", "", "N/A"},
        {"DatoCMS", {}, {}, {"datocms-assets.com"}, "/", "", "N/A"},
        {"Sanity", {}, {}, {"sanity.io"}, "/", "", "N/A"},
        {"Prismic", {}, {}, {"prismic.io"}, "/", "", "N/A"},
        {"Storyblok", {}, {}, {"storyblok.com"}, "/", "", "N/A"},
    };
}

std::string CMSDetector::fetch_url(const std::string& url) {
    apex::Config cfg;
    cfg.timeout = 10;
    apex::HttpClient client(cfg);
    auto resp = client.get(url);
    return resp.body;
}

std::string CMSDetector::extract_version(const std::string& content, const std::string& regex_pattern) {
    if (regex_pattern.empty()) return "";
    try {
        std::regex re(regex_pattern);
        std::smatch match;
        if (std::regex_search(content, match, re) && match.size() > 1) {
            return match[1].str();
        }
    } catch (...) {}
    return "";
}

std::vector<CMSVersion> CMSDetector::detect_with_version(const std::string& base_url) {
    std::vector<CMSVersion> results;
    std::string homepage = fetch_url(base_url);
    
    for (const auto& fp : fingerprints) {
        bool detected = false;
        
        for (const auto& pattern : fp.body_patterns) {
            if (homepage.find(pattern) != std::string::npos) {
                detected = true;
                break;
            }
        }
        
        if (detected && !fp.version_path.empty()) {
            std::string version_url = base_url + fp.version_path;
            std::string version_content = fetch_url(version_url);
            std::string version = extract_version(version_content, fp.version_regex);
            
            if (version.empty()) {
                version = extract_version(homepage, fp.version_regex);
            }
            
            bool outdated = false;
            if (!version.empty() && !fp.latest_version.empty() && fp.latest_version != "N/A") {
                outdated = (version != fp.latest_version);
            }
            
            results.push_back({fp.name, version.empty() ? "Unknown" : version, fp.latest_version, outdated});
        } else if (detected) {
            results.push_back({fp.name, "Unknown", fp.latest_version, false});
        }
    }
    
    return results;
}
