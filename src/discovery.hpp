#pragma once
#include <string>
#include <vector>
#include "http.hpp"
#include "config.hpp"
#include "scanner.hpp"
#include "crawler.hpp"

namespace apex {

struct DiscoveredPath {
    std::string url;
    int status_code;
    size_t size;
    std::string content_type;
    std::string title;
    bool interesting = false;
    std::string reason;
};

class Discovery {
public:
    Discovery(HttpClient &http, const Config &config);

    // Main discovery interface
    std::vector<Finding> discover(const CrawlResult &crawl);

    // Path discovery
    std::vector<DiscoveredPath> brute_paths(const std::string &base_url);
    std::vector<DiscoveredPath> discover_api_endpoints(const std::string &base_url);
    std::vector<DiscoveredPath> discover_admin_panels(const std::string &base_url);
    std::vector<DiscoveredPath> discover_dev_artifacts(const std::string &base_url);
    std::vector<DiscoveredPath> discover_backup_files(const std::string &base_url);

    // Smart 404 detection
    bool is_real_404(const std::string &body, int status_code);
    std::string get_404_signature(const std::string &base_url);

private:
    HttpClient &http_;
    const Config &config_;
    std::string not_found_sig_; // 404 page signature for this target
    size_t not_found_size_ = 0;

    bool is_interesting(const DiscoveredPath &path);
    std::string extract_title(const std::string &body);
};

} // namespace apex
