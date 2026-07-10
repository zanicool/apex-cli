#pragma once
#include <string>
#include <vector>
#include <set>
#include <regex>
#include "http.hpp"

namespace apex {

/// Query Certificate Transparency logs via crt.sh for subdomain enumeration
inline std::set<std::string> enumerate_subdomains_ct(HttpClient &http, const std::string &domain) {
    std::set<std::string> subdomains;

    // Query crt.sh
    std::string url = "https://crt.sh/?q=%25." + domain + "&output=json";
    auto resp = http.get(url);

    if (resp.status_code != 200 || resp.body.empty()) return subdomains;

    // Parse JSON array for name_value fields
    std::regex name_re(R"("name_value"\s*:\s*"([^"]+))");
    auto begin = std::sregex_iterator(resp.body.begin(), resp.body.end(), name_re);
    for (auto it = begin; it != std::sregex_iterator(); ++it) {
        std::string name = (*it)[1].str();
        // Split on newlines (crt.sh returns multiple names per cert)
        std::istringstream ss(name);
        std::string line;
        while (std::getline(ss, line, '\n')) {
            // Clean up
            if (line.empty()) continue;
            if (line[0] == '*') continue; // Skip wildcards
            // Ensure it's a subdomain of our target
            if (line.find(domain) != std::string::npos) {
                subdomains.insert(line);
            }
        }
    }

    return subdomains;
}

/// Query Wayback Machine for historical URLs
inline std::vector<std::string> enumerate_wayback_urls(HttpClient &http, const std::string &domain) {
    std::vector<std::string> urls;

    std::string url = "https://web.archive.org/cdx/search/cdx?url=*." + domain +
                      "/*&output=text&fl=original&collapse=urlkey&limit=500";
    auto resp = http.get(url);

    if (resp.status_code != 200 || resp.body.empty()) return urls;

    std::istringstream ss(resp.body);
    std::string line;
    while (std::getline(ss, line)) {
        if (line.empty()) continue;
        if (line.find("http") == 0) {
            urls.push_back(line);
        }
    }

    return urls;
}

} // namespace apex
