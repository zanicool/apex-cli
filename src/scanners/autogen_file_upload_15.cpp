/// @file scanners/autogen_file_upload_15.cpp
/// @brief Auto-generated scanner: File Upload (15)
///        Checks: Image upload → ImageTragick (C
#include <chrono>
#include <regex>

#include "scanner_base.hpp"

namespace apex {
namespace {

/// Image upload → ImageTragick (CVE-2016-3714)
std::vector<Finding> scan_image_upload_imagetragick_cve_2016_3714(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Image upload → ImageTragick (CVE-2016-3714)
  auto resp = http.get(base + "/api/upload");
  if (resp.status_code != 404) {
    findings.push_back(Finding{"Image upload → ImageTragick (CVE-2016-3714)", "medium", base + "/api/upload",
                               "Upload endpoint found — test for unrestricted file types", "", "",
                               "Status: " + std::to_string(resp.status_code)});
  }

  return findings;
}

}  // namespace

std::vector<Scanner> register_autogen_file_upload_15_scanners() {
  return {
      {"Image upload → ImageTragick (CVE-2016-3714)", scan_image_upload_imagetragick_cve_2016_3714},
  };
}

}  // namespace apex
