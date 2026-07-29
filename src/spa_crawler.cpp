/// @file spa_crawler.cpp
/// @brief Deep SPA/JavaScript crawler: route discovery from JS source.
#include "spa_crawler.hpp"

#include <algorithm>
#include <regex>
#include <set>
#include <sstream>

namespace apex {

SPACrawler::SPACrawler(HttpClient &http, const Config &cfg)
    : http_(http), cfg_(cfg) {}

CrawlResult SPACrawler::deep_crawl(const std::string &base_url,
                                   const CrawlResult &initial) {
  CrawlResult result = initial; // Start with existing crawl data
  std::set<std::string> known_urls(initial.urls.begin(), initial.urls.end());
  std::set<std::string> processed_js;

  // Find all JS files from initial crawl
  auto js_urls = find_js_urls(initial, base_url);

  // Process each JS file
  for (const auto &js_url : js_urls) {
    if (processed_js.count(js_url)) continue;
    processed_js.insert(js_url);

    auto resp = http_.get(js_url);
    if (resp.status_code != 200 || resp.body.empty()) continue;

    // Extract routes from JS
    auto routes = extract_routes(resp.body);
    for (const auto &route : routes) {
      std::string full_url = normalize_url(base_url, route.path);
      if (!known_urls.count(full_url)) {
        known_urls.insert(full_url);
        result.urls.push_back(full_url);
      }
      // Detect framework
      if (!route.framework.empty()) {
        result.technologies.insert(route.framework);
      }
    }

    // Extract API calls
    auto api_calls = extract_api_calls(resp.body);
    for (const auto &api_url : api_calls) {
      std::string full_url = normalize_url(base_url, api_url);
      if (!known_urls.count(full_url)) {
        known_urls.insert(full_url);
        result.urls.push_back(full_url);
      }
    }

    // Find webpack chunks
    auto chunks = extract_webpack_chunks(resp.body, base_url);
    for (const auto &chunk_url : chunks) {
      if (processed_js.count(chunk_url)) continue;
      processed_js.insert(chunk_url);

      auto chunk_resp = http_.get(chunk_url);
      if (chunk_resp.status_code != 200 || chunk_resp.body.empty()) continue;

      // Extract from chunk too
      auto chunk_routes = extract_routes(chunk_resp.body);
      for (const auto &route : chunk_routes) {
        std::string full_url = normalize_url(base_url, route.path);
        if (!known_urls.count(full_url)) {
          known_urls.insert(full_url);
          result.urls.push_back(full_url);
        }
      }

      auto chunk_apis = extract_api_calls(chunk_resp.body);
      for (const auto &api_url : chunk_apis) {
        std::string full_url = normalize_url(base_url, api_url);
        if (!known_urls.count(full_url)) {
          known_urls.insert(full_url);
          result.urls.push_back(full_url);
        }
      }
    }

    // Limit processing
    if (processed_js.size() > 200) break;
  }

  result.is_spa = true;
  return result;
}

std::vector<SPACrawler::RouteInfo>
SPACrawler::extract_routes(const std::string &js_content) {
  std::vector<RouteInfo> routes;
  std::set<std::string> seen_paths;

  // React Router patterns
  // <Route path="/dashboard" component={Dashboard} />
  // { path: '/users/:id', component: UserProfile }
  static const std::regex react_route1(
      R"(path\s*[=:]\s*["'](/[^"']*?)["'])");
  // React Router v6: <Route path="/settings" element={...} />
  static const std::regex react_route2(
      R"(<Route[^>]*path\s*=\s*["']([^"']+)["'])");

  // Vue Router patterns
  // { path: '/home', component: Home }
  static const std::regex vue_route(
      R"(path\s*:\s*["'](/[^"']*?)["'])");

  // Angular patterns
  // { path: 'dashboard', component: DashboardComponent }
  static const std::regex angular_route(
      R"(path\s*:\s*["']([^"']*?)["']\s*,\s*(?:component|loadChildren|redirectTo))");

  // Next.js / file-based routing hints
  static const std::regex nextjs_route(
      R"((?:pages|app)/([^"'\s]+?)(?:\.tsx|\.jsx|\.js|/page))");

  auto process_matches = [&](const std::regex &re, const std::string &framework) {
    std::sregex_iterator it(js_content.begin(), js_content.end(), re);
    std::sregex_iterator end;
    for (; it != end; ++it) {
      std::string path = (*it)[1].str();
      if (path.empty() || path == "/") continue;
      // Ensure path starts with /
      if (path[0] != '/') path = "/" + path;
      // Skip overly generic or invalid paths
      if (path.size() > 200) continue;
      if (path.find(' ') != std::string::npos) continue;

      if (!seen_paths.count(path)) {
        seen_paths.insert(path);
        RouteInfo ri;
        ri.path = path;
        ri.framework = framework;
        routes.push_back(ri);
      }
    }
  };

  process_matches(react_route1, "react");
  process_matches(react_route2, "react");
  process_matches(vue_route, "vue");
  process_matches(angular_route, "angular");
  process_matches(nextjs_route, "nextjs");

  // Generic route-like string patterns: '/api/v1/something'
  static const std::regex generic_route(
      R"(["'](/(?:api|v[0-9]|auth|admin|dashboard|settings|profile|account|users?|posts?|orders?|products?|cart|checkout)[/\w:_\-]*?)["'])");
  process_matches(generic_route, "");

  return routes;
}

std::vector<std::string>
SPACrawler::extract_api_calls(const std::string &js_content) {
  std::vector<std::string> api_urls;
  std::set<std::string> seen;

  // fetch() calls
  static const std::regex fetch_pattern(
      R"(fetch\s*\(\s*["'`]([^"'`]+?)["'`])");
  // axios calls
  static const std::regex axios_pattern(
      R"(axios\.(?:get|post|put|patch|delete)\s*\(\s*["'`]([^"'`]+?)["'`])");
  // axios with baseURL
  static const std::regex axios_base(
      R"(baseURL\s*:\s*["'`]([^"'`]+?)["'`])");
  // XMLHttpRequest
  static const std::regex xhr_pattern(
      R"(\.open\s*\(\s*["'][A-Z]+["']\s*,\s*["'`]([^"'`]+?)["'`])");
  // Generic API URL patterns in strings
  static const std::regex api_string(
      R"(["'`](/api/[^"'`\s]+?)["'`])");
  // $.ajax
  static const std::regex ajax_pattern(
      R"(url\s*:\s*["'`]([^"'`]+?/api[^"'`]*?)["'`])");

  auto extract = [&](const std::regex &re) {
    std::sregex_iterator it(js_content.begin(), js_content.end(), re);
    std::sregex_iterator end;
    for (; it != end; ++it) {
      std::string url = (*it)[1].str();
      if (url.empty() || url.size() > 300) continue;
      if (url.find("${") != std::string::npos) {
        // Template literal — replace variables with placeholder
        url = std::regex_replace(url, std::regex(R"(\$\{[^}]+\})"), "1");
      }
      if (!seen.count(url)) {
        seen.insert(url);
        api_urls.push_back(url);
      }
    }
  };

  extract(fetch_pattern);
  extract(axios_pattern);
  extract(axios_base);
  extract(xhr_pattern);
  extract(api_string);
  extract(ajax_pattern);

  return api_urls;
}

std::vector<std::string>
SPACrawler::extract_webpack_chunks(const std::string &js_content,
                                   const std::string &base_url) {
  std::vector<std::string> chunks;
  std::set<std::string> seen;

  // Webpack chunk patterns
  static const std::regex chunk_pattern1(
      R"(["']([a-zA-Z0-9_\-]+\.chunk\.js(?:\?[^"']*)?)["'])");
  static const std::regex chunk_pattern2(
      R"(["']([a-zA-Z0-9_\-]+\.[a-f0-9]{6,8}\.js)["'])");
  static const std::regex chunk_pattern3(
      R"(["']((?:static|assets|chunks|_next)/[^"'\s]+\.js)["'])");
  // publicPath + chunk filename
  static const std::regex public_path(
      R"((?:publicPath|__webpack_public_path__)\s*[=:]\s*["']([^"']+)["'])");

  std::string pub_path;
  std::smatch pm;
  if (std::regex_search(js_content, pm, public_path)) {
    pub_path = pm[1].str();
  }

  auto extract = [&](const std::regex &re) {
    std::sregex_iterator it(js_content.begin(), js_content.end(), re);
    std::sregex_iterator end;
    for (; it != end && chunks.size() < 50; ++it) {
      std::string chunk = (*it)[1].str();
      std::string full;
      if (!pub_path.empty()) {
        full = normalize_url(base_url, pub_path + chunk);
      } else {
        full = normalize_url(base_url, chunk);
      }
      if (!seen.count(full)) {
        seen.insert(full);
        chunks.push_back(full);
      }
    }
  };

  extract(chunk_pattern1);
  extract(chunk_pattern2);
  extract(chunk_pattern3);

  return chunks;
}

std::vector<std::string>
SPACrawler::find_js_urls(const CrawlResult &crawl,
                         const std::string &base_url) {
  std::vector<std::string> js_urls;
  std::set<std::string> seen;

  for (const auto &url : crawl.urls) {
    std::string lower = url;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower.size() > 3 && lower.find(".js") != std::string::npos &&
        lower.find(".json") == std::string::npos) {
      if (!seen.count(url)) {
        seen.insert(url);
        js_urls.push_back(url);
      }
    }
  }

  // Also fetch main page and extract script tags
  auto resp = http_.get(base_url);
  if (resp.status_code == 200) {
    static const std::regex script_src(
        R"(<script[^>]+src=["']([^"']+\.js[^"']*?)["'])");
    std::sregex_iterator it(resp.body.begin(), resp.body.end(), script_src);
    std::sregex_iterator end;
    for (; it != end; ++it) {
      std::string src = (*it)[1].str();
      std::string full = normalize_url(base_url, src);
      if (!seen.count(full)) {
        seen.insert(full);
        js_urls.push_back(full);
      }
    }
  }

  return js_urls;
}

std::string SPACrawler::normalize_url(const std::string &base,
                                      const std::string &path) {
  if (path.find("http://") == 0 || path.find("https://") == 0) {
    return path;
  }
  if (path.find("//") == 0) {
    auto colon = base.find(':');
    if (colon != std::string::npos) {
      return base.substr(0, colon + 1) + path;
    }
    return "https:" + path;
  }
  if (!path.empty() && path[0] == '/') {
    // Absolute path — extract origin
    static const std::regex origin_re(R"((https?://[^/]+))");
    std::smatch m;
    if (std::regex_search(base, m, origin_re)) {
      return m[1].str() + path;
    }
  }
  // Relative path
  auto last_slash = base.rfind('/');
  if (last_slash != std::string::npos && last_slash > 8) {
    return base.substr(0, last_slash + 1) + path;
  }
  return base + "/" + path;
}

} // namespace apex
