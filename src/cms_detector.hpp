#pragma once
#include <string>
#include <vector>
#include <map>
#include <regex>

struct CMSVersion {
    std::string name;
    std::string version;
    std::string latest_version;
    bool outdated;
};

struct CMSFingerprint {
    std::string name;
    std::vector<std::string> paths;
    std::vector<std::string> headers;
    std::vector<std::string> body_patterns;
    std::string version_path;           // Path to check for version
    std::string version_regex;          // Regex to extract version
    std::string latest_version;         // Known latest version
};

class CMSDetector {
public:
    CMSDetector();
    std::vector<CMSVersion> detect_with_version(const std::string& base_url);
private:
    std::vector<CMSFingerprint> fingerprints;
    void init_fingerprints();
    std::string fetch_url(const std::string& url);
    std::string extract_version(const std::string& content, const std::string& regex_pattern);
};
