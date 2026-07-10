#include "scanner_base.hpp"
#include <regex>
#include <set>

namespace apex {
namespace {

struct SecretPattern {
    std::string name;
    std::string regex;
    std::string severity;
    std::string cwe;
};

static const std::vector<SecretPattern> SECRET_PATTERNS = {
    // AWS
    {"AWS Access Key", R"(AKIA[0-9A-Z]{16})", "critical", "CWE-798"},
    {"AWS Secret Key", R"((?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)[\"'\s:=]+([A-Za-z0-9/+=]{40}))", "critical", "CWE-798"},
    // Google
    {"Google API Key", R"(AIza[0-9A-Za-z\-_]{35})", "high", "CWE-798"},
    {"Google OAuth Client ID", R"(\d{12}-[a-z0-9]{32}\.apps\.googleusercontent\.com)", "medium", "CWE-200"},
    {"GCP Service Account", R"("type"\s*:\s*"service_account")", "critical", "CWE-798"},
    // GitHub
    {"GitHub Token", R"(gh[ps]_[A-Za-z0-9_]{36,255})", "critical", "CWE-798"},
    {"GitHub OAuth", R"(gho_[A-Za-z0-9_]{36,255})", "critical", "CWE-798"},
    // Stripe
    {"Stripe Secret Key", R"(sk_live_[0-9a-zA-Z]{24,99})", "critical", "CWE-798"},
    {"Stripe Publishable Key", R"(pk_live_[0-9a-zA-Z]{24,99})", "low", "CWE-200"},
    // Slack
    {"Slack Token", R"(xox[baprs]-[0-9a-zA-Z-]{10,250})", "high", "CWE-798"},
    {"Slack Webhook", R"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+)", "high", "CWE-798"},
    // Firebase
    {"Firebase Config", R"(apiKey[\"'\s:]+[\"']([A-Za-z0-9_-]{39})[\"'])", "medium", "CWE-200"},
    {"Firebase DB URL", R"(https://[a-z0-9-]+\.firebaseio\.com)", "medium", "CWE-200"},
    // Generic
    {"Private Key", R"(-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----)", "critical", "CWE-321"},
    {"JWT Token", R"(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)", "high", "CWE-200"},
    {"Basic Auth Header", R"(Authorization:\s*Basic\s+[A-Za-z0-9+/=]{10,})", "high", "CWE-798"},
    {"Bearer Token", R"(Bearer\s+[A-Za-z0-9_\-.~+/]+=*)", "medium", "CWE-200"},
    // Passwords
    {"Hardcoded Password", R"((?:password|passwd|pwd|secret|token)[\s]*[=:]+[\s]*[\"']([^\"']{8,})[\"'])", "high", "CWE-798"},
    // Internal URLs
    {"Internal URL", R"(https?://(?:10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|localhost)[:/][^\s\"']+)", "medium", "CWE-200"},
    {"Internal Hostname", R"(https?://[a-z0-9-]+\.(?:internal|local|corp|intranet|dev|staging|test)\.[a-z]+)", "medium", "CWE-200"},
    // Cloud
    {"Azure Connection String", R"(DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+)", "critical", "CWE-798"},
    {"SendGrid Key", R"(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})", "high", "CWE-798"},
    {"Twilio", R"(SK[0-9a-fA-F]{32})", "high", "CWE-798"},
    {"Mailgun", R"(key-[0-9a-zA-Z]{32})", "high", "CWE-798"},
    {"Heroku API Key", R"([hH]eroku[a-zA-Z0-9_]*[=:][\"' ]*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})", "high", "CWE-798"},
    // Database
    {"Database URL", R"((?:mysql|postgres|mongodb|redis)://[^\s\"']+:[^\s\"']+@[^\s\"']+)", "critical", "CWE-798"},
};

std::vector<Finding> scan_js_secrets(const Config &cfg, HttpClient &http, const CrawlResult &crawl) {
    std::vector<Finding> findings;
    if (crawl.urls.empty()) return findings;

    // Collect all JS URLs from crawled pages
    std::set<std::string> js_urls;
    std::string base = base_url_from(crawl.urls[0]);

    // Fetch homepage and extract script sources
    auto home = http.get(base);
    std::regex script_re(R"(<script[^>]*src\s*=\s*["']([^"']+)["'])", std::regex::icase);
    auto begin = std::sregex_iterator(home.body.begin(), home.body.end(), script_re);
    for (auto it = begin; it != std::sregex_iterator(); ++it) {
        std::string src = (*it)[1].str();
        if (src[0] == '/') src = base + src;
        else if (src.find("http") != 0) src = base + "/" + src;
        if (src.find(".js") != std::string::npos) {
            js_urls.insert(src);
        }
    }

    // Also check common JS paths
    std::vector<std::string> common_js = {
        "/app.js", "/main.js", "/bundle.js", "/vendor.js", "/config.js",
        "/env.js", "/settings.js", "/constants.js", "/.env.js",
        "/static/js/main.js", "/assets/js/app.js", "/dist/bundle.js"
    };
    for (auto &path : common_js) {
        js_urls.insert(base + path);
    }

    // Limit to 30 JS files max
    int checked = 0;
    for (auto &js_url : js_urls) {
        if (checked >= 30) break;

        auto resp = http.get(js_url);
        if (resp.status_code != 200) continue;
        if (resp.body.empty() || resp.body.length() < 50) continue;
        // Skip if it's HTML (not actual JS)
        if (resp.body.find("<!DOCTYPE") != std::string::npos || resp.body.find("<html") != std::string::npos) continue;

        checked++;

        // Scan for each secret pattern
        for (auto &pattern : SECRET_PATTERNS) {
            try {
                std::regex re(pattern.regex, std::regex::icase);
                std::smatch m;
                std::string search_area = resp.body.substr(0, 500000); // Limit regex search
                if (std::regex_search(search_area, m, re)) {
                    std::string match = m[0].str();
                    // Truncate the match for display
                    std::string display = match.substr(0, 60);
                    if (match.length() > 60) display += "...";

                    Finding f;
                    f.type = "JS Secret: " + pattern.name;
                    f.severity = pattern.severity;
                    f.url = js_url;
                    f.detail = pattern.name + " found in JavaScript file";
                    f.evidence = display;
                    f.cwe_id = pattern.cwe;
                    f.confidence = 0.85;

                    // Higher confidence for certain patterns
                    if (pattern.name.find("AWS Access") != std::string::npos ||
                        pattern.name.find("Private Key") != std::string::npos ||
                        pattern.name.find("Database URL") != std::string::npos) {
                        f.confidence = 0.95;
                    }

                    findings.push_back(f);
                }
            } catch (...) {
                // Regex error — skip
            }
        }
    }

    return findings;
}

} // namespace

std::vector<Scanner> register_js_secrets_scanners() {
    return {
        {"JS Secrets Scanner", scan_js_secrets},
    };
}

} // namespace apex
