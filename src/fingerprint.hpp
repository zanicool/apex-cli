#pragma once
#include <string>
#include <vector>
#include <map>
#include <set>
#include <regex>

namespace apex {

struct TechFingerprint {
    std::string name;
    std::string version;
    std::string category; // "framework", "library", "server", "cdn", "analytics", "cms", "language"
    double confidence = 0.0;
    std::string evidence;
};

struct FingerprintRule {
    std::string name;
    std::string category;
    // Detection methods
    std::vector<std::string> html_patterns;      // Body string contains
    std::vector<std::string> header_patterns;    // Header key contains value
    std::vector<std::string> cookie_patterns;    // Cookie names
    std::vector<std::string> url_patterns;       // URL paths that indicate tech
    std::vector<std::string> script_patterns;    // <script src="..."> patterns
    std::vector<std::string> meta_patterns;      // <meta name/content patterns
    std::string version_regex;                   // Regex to extract version
    std::string version_source;                  // Where to look: "body", "header:X-Name", "script"
};

class Fingerprinter {
public:
    Fingerprinter();

    // Main fingerprint function — analyzes response and returns all detected tech
    std::vector<TechFingerprint> fingerprint(
        const std::string &body,
        const std::map<std::string, std::string> &headers,
        const std::string &url,
        const std::set<std::string> &discovered_urls = {});

    // Quick fingerprint from just body + headers (used during crawl)
    std::set<std::string> quick_detect(const std::string &body, const std::map<std::string, std::string> &headers);

private:
    std::vector<FingerprintRule> rules_;
    void init_rules();

    std::string extract_version(const std::string &source, const std::string &regex_str);
    std::string extract_version_from_script(const std::string &body, const std::string &lib_pattern);
    std::vector<std::string> extract_script_srcs(const std::string &body);
    std::map<std::string, std::string> extract_meta_tags(const std::string &body);
    std::set<std::string> extract_cookies_from_headers(const std::map<std::string, std::string> &headers);
};

} // namespace apex
