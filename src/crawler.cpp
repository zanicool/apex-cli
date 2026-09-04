/// @file crawler.cpp
/// @brief Web crawler: BFS spider with link/form/parameter extraction.
#include "crawler.hpp"
#include <iostream>
#include <queue>
#include <regex>
#include <set>
#include <sstream>

namespace apex {

namespace {

/// Extract the base URL (scheme + host) from a full URL.
std::string base_url(const std::string &url) {
  auto pos = url.find("://");
  if (pos == std::string::npos) return url;
  auto slash = url.find('/', pos + 3);
  return (slash == std::string::npos) ? url : url.substr(0, slash);
}

/// Resolve a relative URL against a base.
/// Resolve a relative URL against a base. (Definition in apex namespace below.)
} // namespace

std::string resolve_url(const std::string &href, const std::string &page_url) {
  if (href.empty() || href[0] == '#') return "";
  // Absolute URL only if "://" appears in the SCHEME position, i.e. before any
  // '/', '?' or '#'. Otherwise a relative link whose query contains a URL —
  // e.g. "/fetch?url=http://example.com" — would be wrongly treated as
  // absolute and then dropped by the http-prefix filter (a real crawler bug
  // that hid SSRF-style endpoints).
  auto scheme = href.find("://");
  if (scheme != std::string::npos) {
    auto first_delim = href.find_first_of("/?#");
    if (first_delim == std::string::npos || scheme < first_delim)
      return href; // genuinely absolute
  }
  if (href.size() >= 2 && href.substr(0, 2) == "//")
    return "https:" + href;
  std::string base = base_url(page_url);
  if (href[0] == '/') return base + href;
  // Relative path — append to directory of page_url.
  auto last_slash = page_url.rfind('/');
  if (last_slash != std::string::npos && last_slash > page_url.find("://") + 2)
    return page_url.substr(0, last_slash + 1) + href;
  return base + "/" + href;
}

namespace {

/// Extract href/src/action attributes from HTML.
std::vector<std::string> extract_links(const std::string &body,
                                       const std::string &page_url) {
  std::vector<std::string> links;
  // Match href="...", src="...", action="..."
  std::regex link_re(
      R"x((href|src|action)\s*=\s*["']([^"'#][^"']*)["'])x",
      std::regex::icase);
  auto it = std::sregex_iterator(body.begin(), body.end(), link_re);
  for (; it != std::sregex_iterator(); ++it) {
    std::string resolved = resolve_url((*it)[2].str(), page_url);
    if (!resolved.empty()) links.push_back(resolved);
  }
  return links;
}

/// Extract query parameters from a URL.
std::vector<Parameter> extract_query_params(const std::string &url) {
  std::vector<Parameter> params;
  auto qpos = url.find('?');
  if (qpos == std::string::npos) return params;
  std::string query = url.substr(qpos + 1);
  // Remove fragment.
  auto frag = query.find('#');
  if (frag != std::string::npos) query = query.substr(0, frag);

  std::string base = url.substr(0, qpos);
  std::istringstream stream(query);
  std::string pair;
  while (std::getline(stream, pair, '&')) {
    auto eq = pair.find('=');
    std::string name = (eq != std::string::npos) ? pair.substr(0, eq) : pair;
    if (!name.empty())
      params.push_back({base, name, "query", "GET"});
  }
  return params;
}

/// Extract forms and their fields from HTML.
std::vector<Form> extract_forms(const std::string &body,
                                const std::string &page_url) {
  std::vector<Form> forms;
  std::regex form_re(
      R"x(<form[^>]*>([\s\S]*?)</form>)x", std::regex::icase);
  std::regex action_re(
      R"x(action\s*=\s*["']([^"']*)["'])x", std::regex::icase);
  std::regex method_re(
      R"x(method\s*=\s*["']([^"']*)["'])x", std::regex::icase);
  std::regex input_re(
      R"x(<(?:input|textarea|select)[^>]*name\s*=\s*["']([^"']+)["'][^>]*)x",
      std::regex::icase);

  auto it = std::sregex_iterator(body.begin(), body.end(), form_re);
  for (; it != std::sregex_iterator(); ++it) {
    Form form;
    std::string tag = (*it)[0].str();
    std::string inner = (*it)[1].str();

    // Extract action.
    std::smatch am;
    if (std::regex_search(tag, am, action_re))
      form.action = resolve_url(am[1].str(), page_url);
    else
      form.action = page_url;

    // Extract method.
    std::smatch mm;
    if (std::regex_search(tag, mm, method_re))
      form.method = mm[1].str();
    else
      form.method = "GET";

    // Extract input fields.
    auto fi = std::sregex_iterator(inner.begin(), inner.end(), input_re);
    for (; fi != std::sregex_iterator(); ++fi) {
      form.fields.push_back(
          {form.action, (*fi)[1].str(), "body", form.method});
    }

    forms.push_back(form);
  }
  return forms;
}

} // namespace

bool in_scope(const std::string &url, const Config &cfg) {
  // Must contain the target domain.
  if (url.find(cfg.target) != std::string::npos) return true;
  // Check --scope regex if provided.
  if (!cfg.scope.empty()) {
    try {
      std::regex scope_re(cfg.scope, std::regex::icase);
      return std::regex_search(url, scope_re);
    } catch (...) {
      return url.find(cfg.scope) != std::string::npos;
    }
  }
  return false;
}

CrawlResult run_crawler(const Config &cfg, HttpClient &http,
                         const std::vector<std::string> &seeds) {
  CrawlResult result;
  std::set<std::string> visited;
  std::set<std::string> param_keys; // For dedup: "url|name"
  std::queue<std::pair<std::string, int>> queue; // url, depth

  int max_depth = cfg.crawl_depth;
  int max_urls = cfg.max_urls;

  // Seed the queue.
  for (const auto &seed : seeds) {
    if (in_scope(seed, cfg)) {
      queue.push({seed, 0});
      visited.insert(seed);
    }
  }

  while (!queue.empty() && (int)result.urls.size() < max_urls) {
    auto [url, depth] = queue.front();
    queue.pop();

    result.urls.push_back(url);

    // Extract query params from URL itself.
    for (const auto &p : extract_query_params(url)) {
      std::string key = p.url + "|" + p.name;
      if (param_keys.insert(key).second)
        result.params.push_back(p);
    }

    // Don't fetch if at max depth.
    if (depth >= max_depth) continue;

    // Fetch page.
    auto resp = http.get(url);
    if (resp.error.empty() && resp.status_code == 200) {
      // Extract and enqueue links.
      for (const auto &link : extract_links(resp.body, url)) {
        if (visited.count(link) || !in_scope(link, cfg)) continue;
        // Skip non-HTTP.
        if (link.find("http") != 0) continue;
        // Skip static assets. Match the extension PRECISELY at the end of the
        // path (optionally followed by ?query or #fragment). A naive substring
        // check is wrong: ".js" is a substring of ".jsp", which silently
        // dropped every .jsp page (login.jsp, index.jsp, ...) — the crawler
        // then never found the login form or its auth-bypass SQLi.
        auto has_ext = [&](const std::string &ext) {
          // Path portion only (strip query/fragment).
          std::string path = link;
          auto qp = path.find_first_of("?#");
          if (qp != std::string::npos) path = path.substr(0, qp);
          if (path.size() < ext.size()) return false;
          return path.compare(path.size() - ext.size(), ext.size(), ext) == 0;
        };
        if (has_ext(".css") || has_ext(".js") || has_ext(".png") ||
            has_ext(".jpg") || has_ext(".jpeg") || has_ext(".gif") ||
            has_ext(".svg") || has_ext(".woff") || has_ext(".woff2") ||
            has_ext(".ico") || has_ext(".ttf"))
          continue;
        visited.insert(link);
        queue.push({link, depth + 1});
      }

      // Extract forms.
      for (auto &form : extract_forms(resp.body, url)) {
        for (const auto &f : form.fields) {
          std::string key = f.url + "|" + f.name;
          if (param_keys.insert(key).second)
            result.params.push_back(f);
        }
        result.forms.push_back(std::move(form));
      }
    }
  }

  return result;
}

} // namespace apex
