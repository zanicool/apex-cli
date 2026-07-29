#pragma once
#include <string>
#include <vector>
#include <map>
#include <functional>
#include "http.hpp"
#include "config.hpp"
#include "scanner.hpp"
#include "crawler.hpp"

namespace apex {

enum class FuzzStrategy {
    REPLACE,     // Replace param value entirely
    APPEND,      // Append to existing value
    INSERT,      // Insert in middle of value
    TYPE_JUGGLE, // Change type (string→array, int→string)
    BOUNDARY,    // Min/max/overflow values
    FORMAT_STRING, // %s, %x, %n patterns
    UNICODE,     // Unicode normalization attacks
    DOUBLE_ENCODE // Double-encode special chars
};

struct FuzzResult {
    std::string url;
    std::string param;
    std::string payload;
    std::string original_value;
    int status_code = 0;
    size_t response_length = 0;
    int response_time_ms = 0;
    std::string anomaly;      // What was different
    double anomaly_score = 0; // 0-1, higher = more interesting
    std::string evidence;
};

struct FuzzTarget {
    std::string url;
    std::string param;
    std::string original_value;
    std::string method; // GET or POST
    std::string content_type;
};

class Fuzzer {
public:
    Fuzzer(HttpClient &http, const Config &config);

    // Main fuzzing interface
    std::vector<Finding> fuzz_all(const CrawlResult &crawl);
    std::vector<FuzzResult> fuzz_parameter(const FuzzTarget &target);

    // Payload generation
    std::vector<std::string> generate_payloads(const std::string &param_name, const std::string &original_value);
    std::vector<std::string> get_sqli_fuzz();
    std::vector<std::string> get_xss_fuzz();
    std::vector<std::string> get_ssti_fuzz();
    std::vector<std::string> get_cmdi_fuzz();
    std::vector<std::string> get_path_fuzz();
    std::vector<std::string> get_ssrf_fuzz();
    std::vector<std::string> get_header_fuzz();
    std::vector<std::string> get_type_juggle();
    std::vector<std::string> get_boundary_values();
    std::vector<std::string> get_unicode_bypass();

    // Analysis
    bool is_anomalous(const FuzzResult &result, const FuzzResult &baseline);
    Finding classify_anomaly(const FuzzResult &result);

private:
    HttpClient &http_;
    const Config &config_;

    FuzzResult send_fuzz(const FuzzTarget &target, const std::string &payload);
    FuzzResult get_baseline(const FuzzTarget &target);
    std::vector<FuzzTarget> extract_targets(const CrawlResult &crawl);
    std::string mutate_payload(const std::string &payload);
};

} // namespace apex
