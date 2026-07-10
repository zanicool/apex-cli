#include "fingerprint.hpp"
#include <algorithm>
#include <iostream>

namespace apex {

Fingerprinter::Fingerprinter() { init_rules(); }

void Fingerprinter::init_rules() {
    rules_ = {
    // ═══════════════════════════════════════════════
    // JAVASCRIPT FRAMEWORKS & LIBRARIES
    // ═══════════════════════════════════════════════
    {"jQuery", "library",
     {"jquery"}, {}, {}, {},
     {"jquery.min.js", "jquery-", "jquery/"}, {},
     R"(jquery[.-]v?(\d+\.\d+\.\d+))", "script"},

    {"React", "framework",
     {"data-reactroot", "__REACT_DEVTOOLS", "react-app", "_reactRootContainer"}, {}, {}, {},
     {"react.min.js", "react.production", "react-dom"}, {},
     R"(react[.-]v?(\d+\.\d+\.\d+))", "script"},

    {"Vue.js", "framework",
     {"data-v-", "__vue__", "Vue.config", "data-vue-app"}, {}, {}, {},
     {"vue.min.js", "vue.global", "vue@"}, {},
     R"(vue[.-]v?(\d+\.\d+\.\d+))", "script"},

    {"Angular", "framework",
     {"ng-version", "ng-app", "ng-controller", "angular.module"}, {}, {}, {},
     {"angular.min.js", "angular.js", "@angular/core"}, {},
     R"delim(ng-version="(\d+\.\d+\.\d+)")delim", "body"},

    {"Svelte", "framework",
     {"__svelte", "svelte-"}, {}, {}, {},
     {"svelte", ".svelte-"}, {},
     "", ""},

    {"Next.js", "framework",
     {"__next", "_next/static", "__NEXT_DATA__", "next/dist"}, {"x-nextjs-cache", "x-nextjs-matched-path"}, {}, {"/_next/"},
     {"_next/static/chunks"}, {},
     R"(next/(\d+\.\d+[\.\d]*))", "body"},

    {"Nuxt.js", "framework",
     {"__nuxt", "__NUXT__", "_nuxt/"}, {}, {}, {"/_nuxt/"},
     {"_nuxt/"}, {},
     "", ""},

    {"Gatsby", "framework",
     {"___gatsby", "gatsby-"}, {"x-gatsby-cache"}, {}, {},
     {"gatsby-"}, {"generator;Gatsby"},
     "", ""},

    {"Remix", "framework",
     {"__remixContext", "remix-"}, {}, {}, {},
     {"remix"}, {},
     "", ""},

    {"Alpine.js", "library",
     {"x-data", "x-show", "x-bind", "x-on:", "@click"}, {}, {}, {},
     {"alpine", "alpinejs"}, {},
     R"(alpine[.-]v?(\d+\.\d+\.\d+))", "script"},

    {"HTMX", "library",
     {"hx-get", "hx-post", "hx-trigger", "hx-swap", "hx-target"}, {}, {}, {},
     {"htmx.min.js", "htmx.org"}, {},
     R"(htmx[.-]v?(\d+\.\d+\.\d+))", "script"},

    {"Lodash", "library",
     {}, {}, {}, {},
     {"lodash.min.js", "lodash.js", "lodash/"}, {},
     R"(lodash[.-]v?(\d+\.\d+\.\d+))", "script"},

    {"Axios", "library",
     {}, {}, {}, {},
     {"axios.min.js", "axios/"}, {},
     R"(axios[.-]v?(\d+\.\d+\.\d+))", "script"},

    {"Moment.js", "library",
     {}, {}, {}, {},
     {"moment.min.js", "moment-with-locales"}, {},
     R"(moment[.-]v?(\d+\.\d+\.\d+))", "script"},

    {"Bootstrap", "library",
     {"bootstrap", "class=\"container"}, {}, {}, {},
     {"bootstrap.min.js", "bootstrap.min.css", "bootstrap.bundle"}, {},
     R"(bootstrap[.-]v?(\d+\.\d+\.\d+))", "script"},

    {"Tailwind CSS", "library",
     {"tailwindcss", "class=\"flex ", "class=\"grid ", "class=\"bg-"}, {}, {}, {},
     {"tailwind"}, {},
     "", ""},

    {"Font Awesome", "library",
     {"fa-brands", "fa-solid", "fa-regular", "fontawesome"}, {}, {}, {},
     {"font-awesome", "fontawesome", "fa-"}, {},
     R"(font-awesome[/-](\d+\.\d+\.\d+))", "script"},

    {"Three.js", "library",
     {"THREE.Scene", "three.module"}, {}, {}, {},
     {"three.min.js", "three.module.js"}, {},
     R"(three[.-]v?r?(\d+[\d.]*\d))", "script"},

    {"D3.js", "library",
     {"d3.select", "d3-"}, {}, {}, {},
     {"d3.min.js", "d3.v", "d3/"}, {},
     R"(d3[.-]v?(\d+\.\d+\.\d+))", "script"},

    // ═══════════════════════════════════════════════
    // BACKEND FRAMEWORKS
    // ═══════════════════════════════════════════════
    {"Express.js", "framework",
     {}, {"x-powered-by:Express"}, {"connect.sid"}, {},
     {}, {},
     "", ""},

    {"Laravel", "framework",
     {"laravel", "csrf-token"}, {"x-powered-by:Laravel"}, {"laravel_session", "XSRF-TOKEN"}, {},
     {}, {},
     "", ""},

    {"Django", "framework",
     {"csrfmiddlewaretoken", "django"}, {}, {"csrftoken", "django_language", "sessionid"}, {},
     {}, {},
     "", ""},

    {"Flask", "framework",
     {}, {"server:Werkzeug"}, {"session"}, {},
     {}, {},
     R"(Werkzeug/(\d+\.\d+\.\d+))", "header:server"},

    {"Ruby on Rails", "framework",
     {"csrf-param", "authenticity_token"}, {"x-runtime", "x-request-id"}, {"_session_id", "_rails_session"}, {},
     {}, {},
     "", ""},

    {"Spring Boot", "framework",
     {}, {"x-application-context"}, {"JSESSIONID"}, {"/actuator", "/actuator/health"},
     {}, {},
     "", ""},

    {"ASP.NET", "framework",
     {"__VIEWSTATE", "__EVENTVALIDATION", "asp.net"}, {"x-powered-by:ASP.NET", "x-aspnet-version"}, {"ASP.NET_SessionId", ".AspNetCore.Antiforgery"}, {},
     {}, {},
     R"(X-AspNet-Version: (\d+\.\d+[\.\d]*))", "header:x-aspnet-version"},

    {"FastAPI", "framework",
     {}, {}, {}, {"/docs", "/redoc", "/openapi.json"},
     {}, {},
     "", ""},

    {"Symfony", "framework",
     {}, {"x-debug-token"}, {"PHPSESSID", "sf_redirect"}, {},
     {}, {},
     "", ""},

    {"CodeIgniter", "framework",
     {}, {}, {"ci_session", "csrf_cookie_name"}, {},
     {}, {},
     "", ""},

    {"CakePHP", "framework",
     {}, {}, {"CAKEPHP", "csrfToken"}, {},
     {}, {},
     "", ""},

    // ═══════════════════════════════════════════════
    // WEB SERVERS
    // ═══════════════════════════════════════════════
    {"Nginx", "server",
     {}, {"server:nginx"}, {}, {},
     {}, {},
     R"(nginx/(\d+\.\d+[\.\d]*))", "header:server"},

    {"Apache", "server",
     {}, {"server:Apache"}, {}, {},
     {}, {},
     R"(Apache/(\d+\.\d+[\.\d]*))", "header:server"},

    {"IIS", "server",
     {}, {"server:Microsoft-IIS"}, {}, {},
     {}, {},
     R"(Microsoft-IIS/(\d+\.\d+))", "header:server"},

    {"LiteSpeed", "server",
     {}, {"server:LiteSpeed"}, {}, {},
     {}, {},
     R"(LiteSpeed/(\d+\.\d+[\.\d]*))", "header:server"},

    {"Caddy", "server",
     {}, {"server:Caddy"}, {}, {},
     {}, {},
     R"(Caddy/(\d+\.\d+[\.\d]*))", "header:server"},

    {"Envoy", "server",
     {}, {"server:envoy", "x-envoy-upstream-service-time"}, {}, {},
     {}, {},
     "", ""},

    {"Traefik", "server",
     {}, {"server:Traefik"}, {}, {},
     {}, {},
     R"(Traefik/(\d+\.\d+[\.\d]*))", "header:server"},

    // ═══════════════════════════════════════════════
    // CDN & REVERSE PROXY
    // ═══════════════════════════════════════════════
    {"Cloudflare", "cdn",
     {}, {"server:cloudflare", "cf-ray", "cf-cache-status"}, {"__cfruid", "__cf_bm"}, {},
     {}, {},
     "", ""},

    {"Fastly", "cdn",
     {}, {"x-served-by", "x-cache:HIT", "via:.*varnish", "x-fastly-request-id"}, {}, {},
     {}, {},
     "", ""},

    {"Akamai", "cdn",
     {}, {"x-akamai-transformed", "server:AkamaiGHost"}, {}, {},
     {}, {},
     "", ""},

    {"AWS CloudFront", "cdn",
     {}, {"x-amz-cf-id", "x-amz-cf-pop", "via:.*CloudFront"}, {}, {},
     {}, {},
     "", ""},

    {"Vercel", "cdn",
     {}, {"x-vercel-id", "server:Vercel", "x-vercel-cache"}, {}, {},
     {}, {},
     "", ""},

    {"Netlify", "cdn",
     {}, {"server:Netlify", "x-nf-request-id"}, {}, {},
     {}, {},
     "", ""},

    {"Azure CDN", "cdn",
     {}, {"x-ms-ref", "x-azure-ref"}, {}, {},
     {}, {},
     "", ""},

    // ═══════════════════════════════════════════════
    // ANALYTICS & TRACKING
    // ═══════════════════════════════════════════════
    {"Google Analytics", "analytics",
     {"google-analytics.com", "googletagmanager.com", "gtag(", "ga('create"}, {}, {"_ga", "_gid"}, {},
     {"google-analytics.com/analytics.js", "googletagmanager.com/gtag/js"}, {},
     "", ""},

    {"Google Tag Manager", "analytics",
     {"googletagmanager.com/gtm.js", "GTM-"}, {}, {}, {},
     {"googletagmanager.com"}, {},
     R"(GTM-([A-Z0-9]+))", "body"},

    {"Hotjar", "analytics",
     {"hotjar.com", "hjid"}, {}, {"_hj"}, {},
     {"static.hotjar.com"}, {},
     "", ""},

    {"Segment", "analytics",
     {"analytics.js", "segment.com", "analytics.identify"}, {}, {"ajs_"}, {},
     {"cdn.segment.com"}, {},
     "", ""},

    {"Mixpanel", "analytics",
     {"mixpanel.com", "mixpanel.track"}, {}, {"mp_"}, {},
     {"cdn.mxpnl.com"}, {},
     "", ""},

    {"Plausible", "analytics",
     {"plausible.io"}, {}, {}, {},
     {"plausible.io/js"}, {},
     "", ""},

    {"Matomo", "analytics",
     {"matomo.js", "piwik.js", "_paq"}, {}, {"_pk_id", "_pk_ses"}, {},
     {"matomo.js", "piwik.js"}, {},
     "", ""},

    {"Facebook Pixel", "analytics",
     {"fbq(", "facebook.com/tr", "fbevents.js"}, {}, {"_fbp"}, {},
     {"connect.facebook.net/en_US/fbevents.js"}, {},
     "", ""},

    // ═══════════════════════════════════════════════
    // LANGUAGES & RUNTIMES
    // ═══════════════════════════════════════════════
    {"PHP", "language",
     {}, {"x-powered-by:PHP"}, {"PHPSESSID"}, {},
     {}, {},
     R"(PHP/(\d+\.\d+[\.\d]*))", "header:x-powered-by"},

    {"Java", "language",
     {}, {}, {"JSESSIONID"}, {},
     {}, {},
     "", ""},

    {"Python", "language",
     {}, {"server:Python", "server:gunicorn", "server:uvicorn"}, {}, {},
     {}, {},
     R"(Python/(\d+\.\d+[\.\d]*))", "header:server"},

    {"Node.js", "language",
     {}, {"x-powered-by:Express"}, {"connect.sid"}, {},
     {}, {},
     "", ""},

    // ═══════════════════════════════════════════════
    // SECURITY & AUTH
    // ═══════════════════════════════════════════════
    {"reCAPTCHA", "security",
     {"google.com/recaptcha", "g-recaptcha", "grecaptcha"}, {}, {}, {},
     {"google.com/recaptcha/api.js"}, {},
     R"(recaptcha/api.js\?.*v=([a-z0-9]+))", "body"},

    {"hCaptcha", "security",
     {"hcaptcha.com", "h-captcha"}, {}, {}, {},
     {"hcaptcha.com/1/api.js"}, {},
     "", ""},

    {"Turnstile", "security",
     {"challenges.cloudflare.com/turnstile"}, {}, {}, {},
     {"challenges.cloudflare.com/turnstile"}, {},
     "", ""},

    {"Auth0", "security",
     {"auth0.com", "auth0-"}, {}, {"auth0"}, {},
     {"cdn.auth0.com"}, {},
     "", ""},

    {"Okta", "security",
     {"okta.com", "oktacdn"}, {}, {"okta-oauth"}, {},
     {"oktacdn.com"}, {},
     "", ""},

    {"Firebase Auth", "security",
     {"firebase", "firebaseapp.com"}, {}, {}, {},
     {"firebase", "firebaseapp.com"}, {},
     "", ""},

    // ═══════════════════════════════════════════════
    // E-COMMERCE
    // ═══════════════════════════════════════════════
    {"Shopify", "ecommerce",
     {"shopify", "cdn.shopify.com"}, {"x-shopify-stage"}, {"_shopify_"}, {},
     {"cdn.shopify.com"}, {},
     "", ""},

    {"WooCommerce", "ecommerce",
     {"woocommerce", "wc-ajax"}, {}, {"woocommerce_"}, {},
     {"woocommerce"}, {},
     R"(woocommerce/(\d+\.\d+[\.\d]*))", "body"},

    {"Stripe", "ecommerce",
     {"stripe.com", "Stripe("}, {}, {}, {},
     {"js.stripe.com"}, {},
     R"(stripe.com/v(\d+))", "body"},

    {"PayPal", "ecommerce",
     {"paypal.com/sdk"}, {}, {}, {},
     {"paypal.com/sdk/js"}, {},
     "", ""},

    // ═══════════════════════════════════════════════
    // DEVOPS & MONITORING
    // ═══════════════════════════════════════════════
    {"Sentry", "monitoring",
     {"sentry.io", "Sentry.init", "sentry-"}, {"x-sentry-rate-limit"}, {}, {},
     {"browser.sentry-cdn.com", "sentry.io"}, {},
     R"(sentry[.-]v?(\d+\.\d+[\.\d]*))", "script"},

    {"Datadog RUM", "monitoring",
     {"datadoghq.com", "DD_RUM"}, {}, {}, {},
     {"datadoghq.com"}, {},
     "", ""},

    {"New Relic", "monitoring",
     {"newrelic.com", "NREUM", "nr-data.net"}, {}, {}, {},
     {"js-agent.newrelic.com"}, {},
     "", ""},

    {"LogRocket", "monitoring",
     {"logrocket.com", "LogRocket.init"}, {}, {}, {},
     {"cdn.logrocket.io"}, {},
     "", ""},

    // ═══════════════════════════════════════════════
    // BUILD TOOLS (detectable from output)
    // ═══════════════════════════════════════════════
    {"Webpack", "build",
     {"webpackJsonp", "__webpack_require__", "webpackChunk"}, {}, {}, {},
     {}, {},
     "", ""},

    {"Vite", "build",
     {"/@vite/client", "vite/modulepreload"}, {}, {}, {},
     {"@vite/client"}, {},
     "", ""},

    {"Parcel", "build",
     {"parcelRequire"}, {}, {}, {},
     {}, {},
     "", ""},
    };
}

// ═══════════════════════════════════════════════════════════
// DETECTION ENGINE
// ═══════════════════════════════════════════════════════════

std::vector<TechFingerprint> Fingerprinter::fingerprint(
    const std::string &body,
    const std::map<std::string, std::string> &headers,
    const std::string &url,
    const std::set<std::string> &discovered_urls) {

    std::vector<TechFingerprint> results;
    auto scripts = extract_script_srcs(body);
    auto metas = extract_meta_tags(body);
    auto cookies = extract_cookies_from_headers(headers);

    // Lowercase body for case-insensitive matching
    std::string body_lower = body;
    std::transform(body_lower.begin(), body_lower.end(), body_lower.begin(), ::tolower);

    for (auto &rule : rules_) {
        double score = 0.0;
        std::string evidence;
        std::string version;

        // Check HTML body patterns
        for (auto &pattern : rule.html_patterns) {
            std::string pat_lower = pattern;
            std::transform(pat_lower.begin(), pat_lower.end(), pat_lower.begin(), ::tolower);
            if (body_lower.find(pat_lower) != std::string::npos) {
                score += 0.3;
                if (evidence.empty()) evidence = "HTML: \"" + pattern + "\"";
            }
        }

        // Check response headers
        for (auto &pattern : rule.header_patterns) {
            auto colon = pattern.find(':');
            if (colon != std::string::npos) {
                std::string key = pattern.substr(0, colon);
                std::string val = pattern.substr(colon + 1);
                for (auto &h : headers) {
                    std::string hkey = h.first;
                    std::transform(hkey.begin(), hkey.end(), hkey.begin(), ::tolower);
                    std::string hval = h.second;
                    std::transform(hval.begin(), hval.end(), hval.begin(), ::tolower);
                    std::transform(key.begin(), key.end(), key.begin(), ::tolower);
                    std::transform(val.begin(), val.end(), val.begin(), ::tolower);
                    if (hkey.find(key) != std::string::npos && hval.find(val) != std::string::npos) {
                        score += 0.5;
                        evidence = "Header: " + h.first + ": " + h.second;
                    }
                }
            } else {
                // Just check if header key exists
                for (auto &h : headers) {
                    std::string hkey = h.first;
                    std::transform(hkey.begin(), hkey.end(), hkey.begin(), ::tolower);
                    std::string pat_lower = pattern;
                    std::transform(pat_lower.begin(), pat_lower.end(), pat_lower.begin(), ::tolower);
                    if (hkey.find(pat_lower) != std::string::npos) {
                        score += 0.4;
                        evidence = "Header: " + h.first + ": " + h.second;
                    }
                }
            }
        }

        // Check cookies
        for (auto &pattern : rule.cookie_patterns) {
            for (auto &cookie : cookies) {
                if (cookie.find(pattern) != std::string::npos) {
                    score += 0.4;
                    if (evidence.empty()) evidence = "Cookie: " + cookie;
                }
            }
        }

        // Check URL patterns
        for (auto &pattern : rule.url_patterns) {
            if (url.find(pattern) != std::string::npos) {
                score += 0.3;
                if (evidence.empty()) evidence = "URL: " + pattern;
            }
            for (auto &disc_url : discovered_urls) {
                if (disc_url.find(pattern) != std::string::npos) {
                    score += 0.2;
                    break;
                }
            }
        }

        // Check script sources
        for (auto &pattern : rule.script_patterns) {
            std::string pat_lower = pattern;
            std::transform(pat_lower.begin(), pat_lower.end(), pat_lower.begin(), ::tolower);
            for (auto &script : scripts) {
                std::string scr_lower = script;
                std::transform(scr_lower.begin(), scr_lower.end(), scr_lower.begin(), ::tolower);
                if (scr_lower.find(pat_lower) != std::string::npos) {
                    score += 0.4;
                    if (evidence.empty()) evidence = "Script: " + script;
                    // Try version extraction from script URL
                    if (version.empty() && !rule.version_regex.empty() && rule.version_source == "script") {
                        version = extract_version(script, rule.version_regex);
                    }
                }
            }
        }

        // Check meta tags
        for (auto &pattern : rule.meta_patterns) {
            auto semi = pattern.find(';');
            if (semi != std::string::npos) {
                std::string meta_name = pattern.substr(0, semi);
                std::string meta_val = pattern.substr(semi + 1);
                for (auto &m : metas) {
                    if (m.first.find(meta_name) != std::string::npos && m.second.find(meta_val) != std::string::npos) {
                        score += 0.5;
                        if (evidence.empty()) evidence = "Meta: " + m.first + "=" + m.second;
                    }
                }
            }
        }

        // If detected, try to extract version
        if (score >= 0.3 && version.empty() && !rule.version_regex.empty()) {
            if (rule.version_source == "body") {
                version = extract_version(body, rule.version_regex);
            } else if (rule.version_source.find("header:") == 0) {
                std::string hdr_name = rule.version_source.substr(7);
                for (auto &h : headers) {
                    std::string hkey = h.first;
                    std::transform(hkey.begin(), hkey.end(), hkey.begin(), ::tolower);
                    if (hkey == hdr_name) {
                        version = extract_version(h.second, rule.version_regex);
                        break;
                    }
                }
            } else if (rule.version_source == "script") {
                // Already tried above, try body as fallback
                version = extract_version(body, rule.version_regex);
            }
        }

        // Minimum threshold
        if (score >= 0.3) {
            TechFingerprint fp;
            fp.name = rule.name;
            fp.category = rule.category;
            fp.version = version;
            fp.confidence = std::min(score, 1.0);
            fp.evidence = evidence;
            results.push_back(fp);
        }
    }

    // Sort by confidence
    std::sort(results.begin(), results.end(), [](const TechFingerprint &a, const TechFingerprint &b) {
        return a.confidence > b.confidence;
    });

    return results;
}

std::set<std::string> Fingerprinter::quick_detect(const std::string &body, const std::map<std::string, std::string> &headers) {
    std::set<std::string> techs;
    auto results = fingerprint(body, headers, "", {});
    for (auto &r : results) {
        std::string name = r.name;
        std::transform(name.begin(), name.end(), name.begin(), ::tolower);
        // Replace spaces with nothing for compatibility
        name.erase(std::remove(name.begin(), name.end(), ' '), name.end());
        techs.insert(name);
    }
    return techs;
}

// ═══════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════

std::string Fingerprinter::extract_version(const std::string &source, const std::string &regex_str) {
    if (regex_str.empty()) return "";
    try {
        std::regex re(regex_str, std::regex::icase);
        std::smatch m;
        if (std::regex_search(source, m, re) && m.size() > 1) {
            return m[1].str();
        }
    } catch (...) {}
    return "";
}

std::string Fingerprinter::extract_version_from_script(const std::string &body, const std::string &lib_pattern) {
    // Find script tag containing the lib pattern and extract version from URL
    std::regex script_re(R"(<script[^>]*src\s*=\s*["']([^"']*)" + lib_pattern + R"([^"']*)["'])", std::regex::icase);
    std::smatch m;
    if (std::regex_search(body, m, script_re)) {
        std::string url = m[0].str();
        std::regex ver_re(R"((\d+\.\d+\.\d+))");
        std::smatch vm;
        if (std::regex_search(url, vm, ver_re)) return vm[1].str();
    }
    return "";
}

std::vector<std::string> Fingerprinter::extract_script_srcs(const std::string &body) {
    std::vector<std::string> srcs;
    std::regex re(R"(<script[^>]*src\s*=\s*["']([^"']+)["'])", std::regex::icase);
    auto begin = std::sregex_iterator(body.begin(), body.end(), re);
    for (auto it = begin; it != std::sregex_iterator(); ++it) {
        srcs.push_back((*it)[1].str());
    }
    // Also check link href for CSS
    std::regex css_re(R"(<link[^>]*href\s*=\s*["']([^"']+)["'])", std::regex::icase);
    auto css_begin = std::sregex_iterator(body.begin(), body.end(), css_re);
    for (auto it = css_begin; it != std::sregex_iterator(); ++it) {
        srcs.push_back((*it)[1].str());
    }
    return srcs;
}

std::map<std::string, std::string> Fingerprinter::extract_meta_tags(const std::string &body) {
    std::map<std::string, std::string> metas;
    std::regex re(R"(<meta[^>]*name\s*=\s*["']([^"']+)["'][^>]*content\s*=\s*["']([^"']+)["'])", std::regex::icase);
    auto begin = std::sregex_iterator(body.begin(), body.end(), re);
    for (auto it = begin; it != std::sregex_iterator(); ++it) {
        metas[(*it)[1].str()] = (*it)[2].str();
    }
    // Also match content before name
    std::regex re2(R"(<meta[^>]*content\s*=\s*["']([^"']+)["'][^>]*name\s*=\s*["']([^"']+)["'])", std::regex::icase);
    auto begin2 = std::sregex_iterator(body.begin(), body.end(), re2);
    for (auto it = begin2; it != std::sregex_iterator(); ++it) {
        metas[(*it)[2].str()] = (*it)[1].str();
    }
    return metas;
}

std::set<std::string> Fingerprinter::extract_cookies_from_headers(const std::map<std::string, std::string> &headers) {
    std::set<std::string> cookies;
    for (auto &h : headers) {
        std::string key = h.first;
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        if (key == "set-cookie") {
            // Extract cookie name
            auto eq = h.second.find('=');
            if (eq != std::string::npos) {
                cookies.insert(h.second.substr(0, eq));
            }
            cookies.insert(h.second);
        }
    }
    return cookies;
}

} // namespace apex
