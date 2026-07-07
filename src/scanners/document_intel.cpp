/// @file scanners/document_intel.cpp
/// @brief Document/download intelligence: analyzes PDF/file download URLs,
///        document metadata, and file serving infrastructure for tech leakage.
///
/// What download URLs and documents leak:
///   - Backend tech: /wp-content/, /sites/default/files/, /umbraco/media/
///   - Internal paths: /var/www/, C:\inetpub\, /home/user/
///   - Software: "Creator: Microsoft Word", "Producer: wkhtmltopdf"
///   - Usernames: "Author: j.smith", "Last Modified By: admin"
///   - Internal hostnames: \\fileserver\share\, //nas01/docs/
///   - Versions: "LibreOffice 7.4", "Adobe InDesign 18.0"
///   - Timestamps: creation dates reveal work patterns
///   - Printer/scanner info: device names, serial numbers
#include <set>

#include "scanner_base.hpp"

namespace apex {
namespace {

/// Analyze download/file URLs found on the site for tech disclosure.
std::vector<Finding> scan_download_urls(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Collect all file/download links from crawled pages.
  std::set<std::string> file_urls;
  std::regex href_re(R"(href=["']([^"']+\.(pdf|doc|docx|xls|xlsx|ppt|pptx|zip|csv|rtf|odt|ods))[^"']*)");

  for (const auto& url : crawl.urls) {
    auto resp = http.get(url);
    auto it = std::sregex_iterator(resp.body.begin(), resp.body.end(), href_re);
    for (; it != std::sregex_iterator(); ++it) {
      std::string link = (*it)[1].str();
      if (link.find("http") == 0)
        file_urls.insert(link);
      else if (link[0] == '/')
        file_urls.insert(base + link);
      else
        file_urls.insert(base + "/" + link);
    }
  }

  // Also check common download/document paths.
  const std::vector<std::string> doc_paths = {
      "/downloads/",          "/documents/",           "/docs/",      "/files/",     "/media/", "/assets/documents/", "/uploads/",
      "/wp-content/uploads/", "/sites/default/files/", "/fileadmin/", "/typo3conf/",
  };
  for (const auto& path : doc_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 && resp.body.find("Index of") != std::string::npos) {
      findings.push_back(
          {"Document Directory Listing", "medium", base + path, "File directory listing enabled — exposes all documents", "", "", ""});
      // Extract file links from listing.
      auto lit = std::sregex_iterator(resp.body.begin(), resp.body.end(), href_re);
      for (; lit != std::sregex_iterator(); ++lit) file_urls.insert(base + path + (*lit)[1].str());
    }
  }

  // Analyze URL patterns for technology leakage.
  struct TechPattern {
    const char* pattern;
    const char* tech;
    const char* detail;
  };
  const TechPattern url_patterns[] = {
      {"/wp-content/uploads/", "WordPress", "File served via WordPress media library"},
      {"/wp-includes/", "WordPress", "WordPress core file path exposed"},
      {"/sites/default/files/", "Drupal", "Drupal public files directory"},
      {"/fileadmin/", "TYPO3", "TYPO3 fileadmin directory"},
      {"/typo3conf/", "TYPO3", "TYPO3 configuration directory"},
      {"/umbraco/media/", "Umbraco", "Umbraco media path"},
      {"/media/com_", "Joomla", "Joomla component media path"},
      {"/images/stories/", "Joomla", "Joomla legacy stories path"},
      {"/modules/", "PrestaShop/Drupal", "Module-based CMS file path"},
      {"/sitecore/shell/", "Sitecore", "Sitecore shell path"},
      {"/_layouts/", "SharePoint", "SharePoint layouts directory"},
      {"/SiteAssets/", "SharePoint", "SharePoint site assets"},
      {"/Shared%20Documents/", "SharePoint", "SharePoint shared documents"},
      {"/PublishingImages/", "SharePoint", "SharePoint publishing images"},
      {"/dam/", "Adobe Experience Manager", "AEM Digital Asset Manager"},
      {"/content/dam/", "Adobe Experience Manager", "AEM DAM content path"},
      {"/crx/", "Adobe Experience Manager", "AEM CRX repository"},
      {"/magnoliaPublic/", "Magnolia", "Magnolia public resource"},
      {"/alfresco/", "Alfresco", "Alfresco document management"},
      {"/nuxeo/", "Nuxeo", "Nuxeo document platform"},
      {"/download.aspx", "ASP.NET", "ASP.NET download handler"},
      {"/DownloadFile.ashx", "ASP.NET", "ASP.NET generic handler"},
      {"/servlet/", "Java", "Java servlet-based file serving"},
      {"/api/files/", "REST API", "API-based file serving"},
      {"/storage/", "Laravel", "Laravel storage path"},
      {"/public/storage/", "Laravel", "Laravel public storage"},
      {"blob.core.windows.net", "Azure Blob Storage", "Files served from Azure"},
      {".s3.amazonaws.com", "AWS S3", "Files served from S3"},
      {"storage.googleapis.com", "Google Cloud Storage", "Files served from GCS"},
      {"/cdn-cgi/", "Cloudflare", "Cloudflare CDN path"},
      {"cloudfront.net", "AWS CloudFront", "Files served via CloudFront"},
  };

  for (const auto& url : file_urls) {
    for (const auto& pat : url_patterns) {
      if (url.find(pat.pattern) != std::string::npos) {
        findings.push_back({"Download URL Tech Leak", "low", url, std::string(pat.tech) + " — " + pat.detail, "", "", ""});
        break;
      }
    }
  }

  return findings;
}

/// Analyze PDF metadata for author/software/internal path leakage.
std::vector<Finding> scan_pdf_metadata(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Find PDF links.
  std::set<std::string> pdfs;
  std::regex pdf_re(R"(href=["']([^"']+\.pdf)[^"']*)");
  size_t pages_checked = 0;
  for (const auto& url : crawl.urls) {
    if (++pages_checked > 10) break;
    auto resp = http.get(url);
    auto it = std::sregex_iterator(resp.body.begin(), resp.body.end(), pdf_re);
    for (; it != std::sregex_iterator(); ++it) {
      std::string link = (*it)[1].str();
      if (link.find("http") == 0)
        pdfs.insert(link);
      else if (link[0] == '/')
        pdfs.insert(base + link);
      else
        pdfs.insert(base + "/" + link);
    }
  }

  // Download first few bytes of each PDF and extract metadata.
  size_t pdf_limit = std::min(pdfs.size(), size_t(10));
  size_t checked = 0;
  for (const auto& pdf_url : pdfs) {
    if (++checked > pdf_limit) break;
    auto resp = http.get(pdf_url);
    if (resp.status_code != 200 || resp.body.size() < 100) continue;
    if (resp.body.substr(0, 4) != "%PDF") continue;

    // Extract metadata from PDF raw content (simplified parsing).
    std::string detail;
    const std::vector<std::pair<std::string, std::string>> meta_keys = {
        {"/Author", "Author"},   {"/Creator", "Creator"}, {"/Producer", "Producer"},          {"/Title", "Title"},
        {"/Company", "Company"}, {"/Manager", "Manager"}, {"/SourceModified", "Source path"},
    };

    for (const auto& [key, label] : meta_keys) {
      size_t pos = resp.body.find(key);
      if (pos == std::string::npos) continue;
      // Extract value (simplified — between parens or after space).
      size_t start = pos + key.size();
      std::string value;
      if (start < resp.body.size() && resp.body[start] == '(') {
        size_t end = resp.body.find(')', start + 1);
        if (end != std::string::npos) value = resp.body.substr(start + 1, end - start - 1);
      } else if (start < resp.body.size() && resp.body[start] == ' ') {
        size_t end = resp.body.find_first_of("\r\n/", start + 1);
        if (end != std::string::npos) value = resp.body.substr(start + 1, end - start - 1);
      }
      if (!value.empty() && value.size() < 200) detail += label + ": " + value + "; ";
    }

    // Check for internal paths in the PDF.
    const std::vector<std::string> path_indicators = {"C:\\Users\\",  "C:\\Documents", "/home/", "/var/www/", "/Users/", "\\\\",
                                                      "//fileserver", "//nas",         "D:\\",   "E:\\",      "/opt/",   "/srv/"};
    for (const auto& ind : path_indicators) {
      size_t pos = resp.body.find(ind);
      if (pos != std::string::npos) {
        size_t end = resp.body.find_first_of("\r\n\0)", pos);
        std::string path = resp.body.substr(pos, std::min(end - pos, size_t(100)));
        detail += "Internal path: " + path + "; ";
        break;
      }
    }

    if (!detail.empty()) {
      // Determine severity based on what leaked.
      std::string severity = "low";
      if (detail.find("Internal path") != std::string::npos || detail.find("\\\\") != std::string::npos) severity = "medium";
      if (detail.find("C:\\Users\\") != std::string::npos) severity = "medium";  // Leaks username.

      findings.push_back({"PDF Metadata Leak", severity, pdf_url, "Document metadata exposes: " + detail, "", "", ""});
    }
  }

  return findings;
}

/// Analyze HTTP headers on file downloads for server/tech leakage.
std::vector<Finding> scan_download_headers(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Find a few downloadable files.
  std::set<std::string> files;
  std::regex file_re(R"(href=["']([^"']+\.(pdf|doc|docx|xls|xlsx|zip|csv))[^"']*)");
  auto home = http.get(base + "/");
  auto it = std::sregex_iterator(home.body.begin(), home.body.end(), file_re);
  for (; it != std::sregex_iterator(); ++it) {
    std::string link = (*it)[1].str();
    if (link.find("http") == 0)
      files.insert(link);
    else if (link[0] == '/')
      files.insert(base + link);
    if (files.size() >= 5) break;
  }

  for (const auto& url : files) {
    auto resp = http.get(url);
    if (resp.status_code != 200) continue;

    // Check Content-Disposition for internal filenames.
    auto cd = resp.headers.find("Content-Disposition");
    if (cd != resp.headers.end()) {
      // Look for revealing filenames.
      const std::vector<std::string> reveals = {"internal", "draft", "confidential", "private", "backup", "temp", "test", "debug"};
      for (const auto& r : reveals) {
        if (cd->second.find(r) != std::string::npos) {
          findings.push_back({"Revealing Filename", "low", url, "Download filename suggests sensitive content: " + cd->second, "", "", ""});
          break;
        }
      }
    }

    // Check X-Powered-By, Server, etc. on file responses.
    // File endpoints often have different (less hardened) headers.
    auto xpb = resp.headers.find("X-Powered-By");
    if (xpb != resp.headers.end() && xpb->second.size() > 2) {
      findings.push_back({"File Endpoint Tech Leak", "low", url, "File download reveals: X-Powered-By: " + xpb->second, "", "", ""});
    }

    // Check for ASP.NET viewstate or similar in download handlers.
    auto aspnet = resp.headers.find("X-AspNet-Version");
    if (aspnet != resp.headers.end()) {
      findings.push_back({"File Endpoint Tech Leak", "low", url, "File download reveals: X-AspNet-Version: " + aspnet->second, "", "", ""});
    }
  }

  return findings;
}

}  // namespace

std::vector<Scanner> register_document_intel_scanners() {
  return {
      {"Download URL Analysis", scan_download_urls},
      {"PDF Metadata Extraction", scan_pdf_metadata},
      {"Download Header Analysis", scan_download_headers},
  };
}

}  // namespace apex
