#pragma once
#include <string>
#include <vector>
#include <map>
#include <atomic>
#include "http.hpp"
#include "config.hpp"
#include "scanner.hpp"
#include "crawler.hpp"

namespace apex {

struct OOBCallback {
    std::string token;
    std::string payload_type; // ssrf, xxe, ssti, rce
    std::string target_url;
    std::string param;
    std::string timestamp;
    bool triggered = false;
};

struct OOBResult {
    std::string token;
    std::string source_ip;
    std::string user_agent;
    std::string dns_query;
    bool is_dns = false;
    bool is_http = false;
};

class OOBDetector {
public:
    OOBDetector(HttpClient &http, const Config &config);

    // Generate unique callback URLs
    std::string generate_token();
    std::string get_callback_url(const std::string &token);
    std::string get_dns_canary(const std::string &token);

    // Inject OOB payloads
    std::vector<Finding> inject_and_check(const CrawlResult &crawl);

    // Payload generators with OOB callbacks
    std::vector<std::string> get_ssrf_oob_payloads(const std::string &token);
    std::vector<std::string> get_xxe_oob_payloads(const std::string &token);
    std::vector<std::string> get_rce_oob_payloads(const std::string &token);
    std::vector<std::string> get_ssti_oob_payloads(const std::string &token);

    // Check if callbacks were received (via interact.sh or custom server)
    bool check_callback(const std::string &token);
    std::vector<OOBResult> poll_callbacks();

    // Set the OOB server (interact.sh, burp collaborator, or custom)
    void set_server(const std::string &server) { oob_server_ = server; }

private:
    HttpClient &http_;
    const Config &config_;
    std::string oob_server_;
    std::vector<OOBCallback> pending_;
    int token_counter_ = 0;
};

} // namespace apex
