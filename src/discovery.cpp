#include "discovery.hpp"
#include <algorithm>
#include <iostream>
#include <regex>

namespace apex {

Discovery::Discovery(HttpClient &http, const Config &config)
    : http_(http), config_(config) {}

std::vector<Finding> Discovery::discover(const CrawlResult &crawl) {
    std::vector<Finding> findings;
    if (crawl.urls.empty()) return findings;

    std::string base = crawl.urls[0];
    auto proto = base.find("://");
    if (proto != std::string::npos) {
        auto slash = base.find('/', proto + 3);
        if (slash != std::string::npos) base = base.substr(0, slash);
    }

    // Learn 404 signature
    not_found_sig_ = get_404_signature(base);

    std::cout << "  [discovery] Brute-forcing paths on " << base << "\n";

    auto paths = brute_paths(base);
    auto apis = discover_api_endpoints(base);
    auto admins = discover_admin_panels(base);
    auto devs = discover_dev_artifacts(base);

    auto process = [&](const std::vector<DiscoveredPath> &discovered) {
        for (auto &d : discovered) {
            if (d.interesting) {
                Finding f;
                f.url = d.url;
                f.type = "Hidden Endpoint Discovered";
                f.severity = d.status_code == 200 ? "medium" : "low";
                f.detail = d.reason;
                f.confidence = 0.8;
                f.evidence = "Status: " + std::to_string(d.status_code) + ", Size: " + std::to_string(d.size);
                if (d.reason.find("admin") != std::string::npos || d.reason.find("debug") != std::string::npos) {
                    f.severity = "high";
                    f.confidence = 0.9;
                }
                findings.push_back(f);
            }
        }
    };

    process(paths);
    process(apis);
    process(admins);
    process(devs);

    std::cout << "  [discovery] Found " << findings.size() << " hidden endpoints\n";
    return findings;
}

std::vector<DiscoveredPath> Discovery::brute_paths(const std::string &base_url) {
    std::vector<DiscoveredPath> results;

    const std::vector<std::string> paths = {
        "/.git/HEAD", "/.git/config", "/.env", "/.env.local", "/.env.production",
        "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
        "/wp-admin/", "/wp-login.php", "/wp-json/wp/v2/users",
        "/admin", "/admin/", "/administrator/", "/login", "/dashboard",
        "/api", "/api/v1", "/api/v2", "/api/docs", "/api/swagger.json",
        "/swagger-ui.html", "/swagger.json", "/openapi.json", "/api-docs",
        "/graphql", "/graphiql", "/altair", "/playground",
        "/debug", "/trace", "/status", "/health", "/healthz", "/ready",
        "/metrics", "/prometheus", "/actuator", "/actuator/env", "/actuator/heapdump",
        "/server-status", "/server-info", "/.htaccess", "/.htpasswd",
        "/phpinfo.php", "/info.php", "/test.php", "/debug.php",
        "/console", "/_debug", "/__debug__", "/_profiler",
        "/elmah.axd", "/trace.axd", "/telescope", "/horizon",
        "/phpmyadmin/", "/pma/", "/myadmin/", "/mysql/",
        "/adminer.php", "/adminer/",
        "/.DS_Store", "/Thumbs.db", "/web.config", "/crossdomain.xml",
        "/package.json", "/composer.json", "/Gemfile", "/requirements.txt",
        "/Dockerfile", "/docker-compose.yml", "/.dockerenv",
        "/config.yml", "/config.yaml", "/config.json", "/settings.json",
        "/.vscode/", "/.idea/", "/nbproject/",
        "/backup/", "/backups/", "/dump/", "/export/", "/temp/", "/tmp/",
        "/.svn/entries", "/.hg/", "/CVS/Root",
        "/cgi-bin/", "/cgi-bin/test-cgi", "/cgi-bin/printenv",
        "/server/", "/internal/", "/private/", "/secret/",
        "/jenkins/", "/ci/", "/build/", "/deploy/",
        "/graphql/schema", "/.well-known/openid-configuration",
        "/oauth/token", "/oauth/authorize", "/auth/realms",
        "/api/users", "/api/admin", "/api/config",
        "/v1/", "/v2/", "/v3/", "/latest/",
        "/socket.io/", "/ws/", "/websocket",
    };

    for (auto &path : paths) {
        auto resp = http_.get(base_url + path);
        if (resp.status_code == 0) continue;

        DiscoveredPath dp;
        dp.url = base_url + path;
        dp.status_code = resp.status_code;
        dp.size = resp.body.size();
        dp.title = extract_title(resp.body);

        // Check if it's a real page (not a 404/redirect to login)
        if (resp.status_code == 200 && !is_real_404(resp.body, resp.status_code)) {
            dp.interesting = is_interesting(dp);
            if (dp.interesting) {
                dp.reason = "Accessible endpoint: " + path;
            }
        } else if (resp.status_code == 401 || resp.status_code == 403) {
            // Protected but exists
            dp.interesting = true;
            dp.reason = "Protected endpoint (" + std::to_string(resp.status_code) + "): " + path;
        }

        if (dp.interesting) results.push_back(dp);
    }
    return results;
}

std::vector<DiscoveredPath> Discovery::discover_api_endpoints(const std::string &base_url) {
    std::vector<DiscoveredPath> results;

    const std::vector<std::string> api_paths = {
        "/api/v1/users", "/api/v1/admin", "/api/v1/config", "/api/v1/debug",
        "/api/v2/users", "/api/v1/internal", "/api/v1/swagger",
        "/api/users/me", "/api/profile", "/api/settings", "/api/version",
        "/api/graphql", "/api/health", "/api/__schema",
        "/rest/api/latest/serverInfo", "/rest/api/2/myself",
        "/_api/", "/api/v1/metadata", "/api/v1/export",
    };

    for (auto &path : api_paths) {
        auto resp = http_.get(base_url + path);
        if (resp.status_code == 200 && !is_real_404(resp.body, resp.status_code)) {
            DiscoveredPath dp;
            dp.url = base_url + path;
            dp.status_code = resp.status_code;
            dp.size = resp.body.size();
            dp.interesting = true;
            dp.reason = "API endpoint accessible: " + path;

            // Check for JSON response (likely real API)
            if (resp.body.size() > 2 && (resp.body[0] == '{' || resp.body[0] == '[')) {
                dp.reason += " (JSON response)";
            }
            results.push_back(dp);
        }
    }
    return results;
}

std::vector<DiscoveredPath> Discovery::discover_admin_panels(const std::string &base_url) {
    std::vector<DiscoveredPath> results;

    const std::vector<std::string> admin_paths = {
        "/admin", "/admin/login", "/admin/dashboard", "/administrator",
        "/panel", "/cpanel", "/webadmin", "/siteadmin",
        "/backoffice", "/management", "/manage", "/portal",
        "/cms", "/cms/admin", "/wp-admin", "/user/admin",
    };

    for (auto &path : admin_paths) {
        auto resp = http_.get(base_url + path);
        if ((resp.status_code == 200 || resp.status_code == 302) && !is_real_404(resp.body, resp.status_code)) {
            if (resp.body.find("password") != std::string::npos || resp.body.find("login") != std::string::npos ||
                resp.body.find("username") != std::string::npos) {
                DiscoveredPath dp;
                dp.url = base_url + path;
                dp.status_code = resp.status_code;
                dp.size = resp.body.size();
                dp.interesting = true;
                dp.reason = "Admin panel with login form: " + path;
                results.push_back(dp);
            }
        }
    }
    return results;
}

std::vector<DiscoveredPath> Discovery::discover_dev_artifacts(const std::string &base_url) {
    std::vector<DiscoveredPath> results;

    const std::vector<std::string> dev_paths = {
        "/.git/HEAD", "/.env", "/debug/vars", "/server-status",
        "/.svn/entries", "/phpinfo.php", "/actuator/env",
        "/telescope", "/horizon", "/_profiler", "/elmah.axd",
        "/webpack-stats.json", "/stats.json", "/build-info.json",
        "/version.json", "/revision", "/commit",
        "/source", "/src/", "/debug/pprof/",
    };

    for (auto &path : dev_paths) {
        auto resp = http_.get(base_url + path);
        if (resp.status_code == 200 && !is_real_404(resp.body, resp.status_code) && resp.body.size() > 10) {
            DiscoveredPath dp;
            dp.url = base_url + path;
            dp.status_code = resp.status_code;
            dp.size = resp.body.size();
            dp.interesting = true;
            dp.reason = "Development artifact exposed: " + path;
            results.push_back(dp);
        }
    }
    return results;
}

std::string Discovery::get_404_signature(const std::string &base_url) {
    // Request a path that definitely doesn't exist
    auto resp = http_.get(base_url + "/apex_nonexistent_path_xyzzy_12345");
    not_found_size_ = resp.body.size();
    // Take a hash-like signature (first 100 chars + size)
    return resp.body.substr(0, std::min((size_t)100, resp.body.size()));
}

bool Discovery::is_real_404(const std::string &body, int status_code) {
    if (status_code == 404) return true;

    // Compare to known 404 signature
    if (!not_found_sig_.empty()) {
        std::string sig = body.substr(0, std::min((size_t)100, body.size()));
        if (sig == not_found_sig_) return true;
        // Size-based: within 10% of 404 size
        if (not_found_size_ > 0 && body.size() > 0) {
            double ratio = (double)body.size() / not_found_size_;
            if (ratio > 0.9 && ratio < 1.1) return true;
        }
    }

    // Common 404 indicators in body
    std::string lower = body.substr(0, 500);
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower.find("page not found") != std::string::npos ||
        lower.find("404") != std::string::npos ||
        lower.find("not found") != std::string::npos ||
        lower.find("does not exist") != std::string::npos) {
        return true;
    }

    return false;
}

bool Discovery::is_interesting(const DiscoveredPath &path) {
    // Skip if it's just a generic page
    if (path.size < 50) return false;

    // Known interesting paths
    std::string url = path.url;
    if (url.find(".git") != std::string::npos || url.find(".env") != std::string::npos ||
        url.find("admin") != std::string::npos || url.find("debug") != std::string::npos ||
        url.find("actuator") != std::string::npos || url.find("phpinfo") != std::string::npos ||
        url.find("swagger") != std::string::npos || url.find("graphql") != std::string::npos ||
        url.find("graphiql") != std::string::npos || url.find("metrics") != std::string::npos ||
        url.find("telescope") != std::string::npos || url.find("horizon") != std::string::npos ||
        url.find("api-docs") != std::string::npos || url.find("openapi") != std::string::npos) {
        return true;
    }

    return false;
}

std::string Discovery::extract_title(const std::string &body) {
    std::regex title_re("<title[^>]*>([^<]+)</title>", std::regex::icase);
    std::smatch m;
    if (std::regex_search(body, m, title_re)) return m[1].str();
    return "";
}

} // namespace apex
