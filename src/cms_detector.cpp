#include "cms_detector.hpp"

#include <algorithm>

#include "config.hpp"
#include "http.hpp"

CMSDetector::CMSDetector() { init_fingerprints(); }

void CMSDetector::init_fingerprints() {
  fingerprints = {
      // === Tier S: 1-20 ===
      {"WordPress", {"/wp-admin/", "/wp-content/"}, {}, {"wp-content"}, "/wp-includes/version.php", "wp_version.*?([0-9.]+)", "6.5.3"},
      {"Joomla",
       {"/administrator/"},
       {},
       {"Joomla!"},
       "/administrator/manifests/files/joomla.xml",
       "<version>([0-9.]+)</version>",
       "5.1.0"},
      {"Drupal", {"/misc/drupal.js"}, {"X-Generator"}, {"Drupal.settings"}, "/core/lib/Drupal.php", "VERSION = '([0-9.]+)'", "10.2.6"},
      {"Magento", {"/skin/frontend/"}, {}, {"Mage.Cookies"}, "/js/mage/cookies.js", "Magento.*?([0-9.]+)", "2.4.7"},
      {"TYPO3", {"/typo3/"}, {"X-TYPO3-Parsetime"}, {"TYPO3"}, "/typo3/", "TYPO3.*?([0-9.]+)", "13.1.0"},
      {"PrestaShop", {"/modules/"}, {}, {"prestashop"}, "/config/settings.inc.php", "_PS_VERSION_.*?'([0-9.]+)'", "8.1.5"},
      {"OpenCart", {"/catalog/"}, {}, {"catalog/view/javascript"}, "/admin/index.php", "OpenCart ([0-9.]+)", "4.0.2.3"},
      {"WooCommerce",
       {"/wp-content/plugins/woocommerce/"},
       {},
       {"woocommerce"},
       "/wp-content/plugins/woocommerce/readme.txt",
       "Stable tag: ([0-9.]+)",
       "8.8.3"},
      {"phpMyAdmin", {"/phpmyadmin/"}, {}, {"phpMyAdmin"}, "/README", "phpMyAdmin.*?([0-9.]+)", "5.2.1"},
      {"MediaWiki", {"/wiki/"}, {"X-Powered-By"}, {"mediawiki"}, "/api.php?action=siteinfo&format=json", "generator.*?([0-9.]+)", "1.41.0"},
      {"vBulletin", {"/vb/"}, {}, {"vBulletin"}, "/", "vBulletin.*?([0-9.]+)", "5.7.5"},
      {"phpBB", {"/phpBB/"}, {}, {"phpBB"}, "/docs/CHANGELOG.html", "phpBB ([0-9.]+)", "3.3.11"},
      {"Craft CMS", {"/cpresources/"}, {"X-Powered-By"}, {"Craft."}, "/", "Craft CMS ([0-9.]+)", "5.1.0"},
      {"Ghost", {"/ghost/"}, {"X-Powered-By"}, {"ghost-"}, "/ghost/api/", "version.*?([0-9.]+)", "5.82.0"},
      {"Concrete CMS", {"/concrete/"}, {}, {"concrete5"}, "/concrete/config/concrete.php", "version.*?([0-9.]+)", "9.2.8"},
      {"Liferay", {"/web/guest"}, {"Liferay-Portal"}, {"Liferay"}, "/", "Liferay.*?([0-9.]+)", "7.4.3"},
      {"DotNetNuke", {"/DesktopModules/"}, {}, {"DNN"}, "/", "DNN.*?([0-9.]+)", "9.13.3"},
      {"Umbraco", {"/umbraco/"}, {"X-Umbraco-Version"}, {"Umbraco"}, "/", "X-Umbraco-Version: ([0-9.]+)", "13.3.0"},
      {"Sitecore", {"/sitecore/"}, {}, {"Sitecore"}, "/sitecore/shell/sitecore.version.xml", "<version>([0-9.]+)</version>", "10.3.1"},
      {"Kentico", {"/CMSPages/"}, {}, {"Kentico"}, "/CMSPages/GetDocLink.ashx", "Kentico.*?([0-9.]+)", "13.0.130"},

      // === Headless / Modern: 21-40 ===
      {"Strapi", {"/admin"}, {"X-Powered-By"}, {"strapi"}, "/admin/", "strapi.*?([0-9.]+)", "4.22.0"},
      {"Directus", {"/admin/"}, {}, {"directus"}, "/server/info", "version.*?([0-9.]+)", "10.10.0"},
      {"Contentful", {}, {}, {"contentful.com"}, "/", "", "N/A"},
      {"Sanity", {}, {}, {"sanity.io"}, "/", "", "N/A"},
      {"Payload CMS", {"/admin"}, {}, {"payload"}, "/api/globals", "version.*?([0-9.]+)", "2.11.0"},
      {"KeystoneJS", {"/admin"}, {}, {"keystone"}, "/", "keystone.*?([0-9.]+)", "6.3.0"},
      {"Cockpit CMS", {"/cockpit/"}, {}, {"cockpit"}, "/cockpit/", "cockpit.*?([0-9.]+)", "2.8.0"},
      {"Prismic", {}, {}, {"prismic.io"}, "/", "", "N/A"},
      {"DatoCMS", {}, {}, {"datocms-assets.com"}, "/", "", "N/A"},
      {"Hygraph", {}, {}, {"hygraph.com"}, "/", "", "N/A"},
      {"Storyblok", {}, {}, {"storyblok.com"}, "/", "", "N/A"},
      {"ButterCMS", {}, {}, {"buttercms.com"}, "/", "", "N/A"},
      {"Builder.io", {}, {}, {"builder.io"}, "/", "", "N/A"},
      {"Netlify CMS", {}, {}, {"netlify"}, "/admin/config.yml", "", "N/A"},
      {"Decap CMS", {}, {}, {"decap"}, "/admin/config.yml", "", "N/A"},
      {"TinaCMS", {}, {}, {"tina.io"}, "/", "", "N/A"},
      {"Agility CMS", {}, {}, {"agilitycms.com"}, "/", "", "N/A"},
      {"Bloomreach", {"/cms/"}, {}, {"bloomreach"}, "/", "bloomreach.*?([0-9.]+)", "15.0"},
      {"Core dna", {}, {}, {"coredna.com"}, "/", "", "N/A"},
      {"Kontent.ai", {}, {}, {"kontent.ai"}, "/", "", "N/A"},

      // === E-commerce: 41-55 ===
      {"Shopify", {}, {"X-ShopId"}, {"cdn.shopify.com"}, "/", "", "N/A"},
      {"BigCommerce", {}, {}, {"bigcommerce.com"}, "/", "", "N/A"},
      {"Saleor", {"/graphql/"}, {}, {"saleor"}, "/graphql/", "saleor.*?([0-9.]+)", "3.19.0"},
      {"Medusa", {"/store/"}, {}, {"medusa"}, "/store/", "medusa.*?([0-9.]+)", "1.20.0"},
      {"Sylius", {"/admin/"}, {}, {"sylius"}, "/", "Sylius.*?([0-9.]+)", "1.12.0"},
      {"nopCommerce", {"/Admin/"}, {}, {"nopCommerce"}, "/", "nopCommerce.*?([0-9.]+)", "4.70.0"},
      {"osCommerce", {"/catalog/"}, {}, {"osCommerce"}, "/", "osCommerce.*?([0-9.]+)", "4.0"},
      {"Zen Cart", {"/includes/"}, {}, {"Zen Cart"}, "/", "Zen Cart.*?([0-9.]+)", "1.5.8"},
      {"CS-Cart", {"/skins/"}, {}, {"cs-cart"}, "/", "CS-Cart.*?([0-9.]+)", "4.17.0"},
      {"VirtueMart", {"/components/com_virtuemart/"}, {}, {"VirtueMart"}, "/", "VirtueMart.*?([0-9.]+)", "4.2.0"},
      {"Spree Commerce", {"/spree/"}, {}, {"spree"}, "/", "spree.*?([0-9.]+)", "4.7.0"},
      {"Adobe Commerce", {"/skin/frontend/"}, {}, {"Magento"}, "/magento_version", "([0-9.]+)", "2.4.7"},
      {"CommerceTools", {}, {}, {"commercetools.com"}, "/", "", "N/A"},
      {"Vendure", {"/admin/"}, {}, {"vendure"}, "/", "vendure.*?([0-9.]+)", "2.2.0"},
      {"Drupal Commerce", {"/modules/commerce/"}, {}, {"commerce"}, "/", "commerce.*?([0-9.]+)", "2.36.0"},

      // === Wiki / Forums / Communities: 56-70 ===
      {"Discourse", {"/categories"}, {}, {"discourse"}, "/", "discourse.*?([0-9.]+)", "3.2.0"},
      {"Flarum", {"/api/"}, {}, {"flarum"}, "/api/", "flarum.*?([0-9.]+)", "1.8.5"},
      {"XenForo", {"/community/"}, {}, {"XenForo"}, "/", "XenForo.*?([0-9.]+)", "2.2.15"},
      {"NodeBB", {"/api/"}, {}, {"nodebb"}, "/api/config", "version.*?([0-9.]+)", "3.6.0"},
      {"BookStack", {"/books/"}, {}, {"BookStack"}, "/", "BookStack.*?([0-9.]+)", "24.02"},
      {"DokuWiki", {"/doku.php"}, {}, {"DokuWiki"}, "/doku.php", "DokuWiki.*?([0-9.]+)", "2024-02-06"},
      {"Wiki.js", {}, {}, {"wiki.js"}, "/graphql", "wiki.*?([0-9.]+)", "2.5.303"},
      {"Confluence", {"/login.action"}, {"X-Confluence"}, {"Confluence"}, "/", "Confluence.*?([0-9.]+)", "8.8.0"},
      {"Tiki Wiki", {"/tiki-index.php"}, {}, {"Tiki"}, "/", "Tiki.*?([0-9.]+)", "27.0"},
      {"MoinMoin", {"/FrontPage"}, {}, {"MoinMoin"}, "/SystemInfo", "MoinMoin.*?([0-9.]+)", "2.0.0"},
      {"MyBB", {"/member.php"}, {}, {"MyBB"}, "/", "MyBB.*?([0-9.]+)", "1.8.37"},
      {"Simple Machines Forum", {"/index.php?action=forum"}, {}, {"SMF"}, "/", "SMF ([0-9.]+)", "2.1.4"},
      {"Vanilla Forums", {"/discussions"}, {}, {"Vanilla"}, "/", "Vanilla.*?([0-9.]+)", "4.3.0"},
      {"bbPress", {"/forums/"}, {}, {"bbpress"}, "/wp-content/plugins/bbpress/readme.txt", "Stable tag: ([0-9.]+)", "2.6.9"},
      {"AnswerHub", {"/questions/"}, {}, {"AnswerHub"}, "/", "AnswerHub.*?([0-9.]+)", "1.7.0"},

      // === Enterprise / DXP: 71-85 ===
      {"Adobe Experience Manager", {"/crx/de"}, {}, {"jcr_root"}, "/system/console/bundles.json", "([0-9.]+)", "6.5.19"},
      {"SharePoint",
       {"/_layouts/"},
       {"MicrosoftSharePointTeamServices"},
       {"SharePoint"},
       "/",
       "MicrosoftSharePointTeamServices: ([0-9.]+)",
       "16.0"},
      {"OpenText", {"/otcs/"}, {}, {"OpenText"}, "/", "OpenText.*?([0-9.]+)", "23.4"},
      {"Alfresco", {"/share/"}, {}, {"Alfresco"}, "/alfresco/api/-default-/public/alfresco/versions/1", "version.*?([0-9.]+)", "23.2"},
      {"Magnolia", {"/magnoliaAuthor/"}, {}, {"magnolia"}, "/", "magnolia.*?([0-9.]+)", "6.2.40"},
      {"Acquia", {}, {}, {"acquia.com"}, "/", "", "N/A"},
      {"Bloomreach Experience", {"/cms/"}, {}, {"hippo"}, "/", "hippo.*?([0-9.]+)", "15.0"},
      {"Oracle WebCenter", {"/webcenter/"}, {}, {"WebCenter"}, "/", "WebCenter.*?([0-9.]+)", "12.2.1"},
      {"HCL Digital Experience", {"/wps/"}, {}, {"WebSphere"}, "/", "WebSphere.*?([0-9.]+)", "9.5"},
      {"Jahia", {"/cms/"}, {}, {"jahia"}, "/", "jahia.*?([0-9.]+)", "8.1.0"},
      {"SDL Tridion", {"/WebUI/"}, {}, {"Tridion"}, "/", "Tridion.*?([0-9.]+)", "11.0"},
      {"Crownpeak", {}, {}, {"crownpeak.com"}, "/", "", "N/A"},
      {"OpenCms", {"/opencms/"}, {}, {"OpenCms"}, "/", "OpenCms.*?([0-9.]+)", "16.0"},
      {"Plone", {"/@@overview-controlpanel"}, {"X-Powered-By"}, {"Plone"}, "/", "Plone.*?([0-9.]+)", "6.0.9"},
      {"eZ Platform", {"/ez/"}, {}, {"eZ Platform"}, "/", "eZ.*?([0-9.]+)", "4.6.0"},

      // === Static / Git-based: 86-100 ===
      {"Hugo", {}, {}, {"Hugo"}, "/", "Hugo.*?([0-9.]+)", "0.124.0"},
      {"Jekyll", {}, {}, {"jekyll"}, "/", "jekyll.*?([0-9.]+)", "4.3.3"},
      {"Eleventy", {}, {}, {"eleventy"}, "/", "", "N/A"},
      {"Astro", {}, {}, {"astro"}, "/", "", "N/A"},
      {"Gatsby", {}, {}, {"gatsby"}, "/", "gatsby.*?([0-9.]+)", "5.13.0"},
      {"Nuxt Content", {}, {}, {"nuxt"}, "/", "nuxt.*?([0-9.]+)", "3.11.0"},
      {"Docusaurus", {}, {}, {"docusaurus"}, "/", "docusaurus.*?([0-9.]+)", "3.2.0"},
      {"MkDocs", {}, {}, {"mkdocs"}, "/", "mkdocs.*?([0-9.]+)", "1.5.3"},
      {"VuePress", {}, {}, {"vuepress"}, "/", "vuepress.*?([0-9.]+)", "2.0.0"},
      {"Hexo", {}, {}, {"Hexo"}, "/", "Hexo.*?([0-9.]+)", "7.1.0"},
      {"Publii", {}, {}, {"publii"}, "/", "", "N/A"},
      {"Forestry", {}, {}, {"forestry.io"}, "/", "", "N/A"},
      {"Retype", {}, {}, {"retype"}, "/", "", "N/A"},
      {"Docsify", {}, {}, {"docsify"}, "/", "docsify.*?([0-9.]+)", "4.13.1"},
      {"Quartz", {}, {}, {"quartz"}, "/", "", "N/A"},
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
  } catch (...) {
  }
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
