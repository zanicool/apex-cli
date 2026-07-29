/// @file dom_xss.cpp
/// @brief DOM XSS detection engine: source-to-sink analysis in JavaScript.
#include "dom_xss.hpp"

#include <algorithm>
#include <regex>
#include <set>
#include <sstream>

namespace apex {

DOMXSSDetector::DOMXSSDetector(HttpClient &http, const Config &cfg)
    : http_(http), cfg_(cfg) {}

std::vector<Finding> DOMXSSDetector::detect(const CrawlResult &crawl) {
  std::vector<Finding> findings;
  std::set<std::string> processed_urls;

  auto js_urls = find_js_urls(crawl);

  for (const auto &js_url : js_urls) {
    if (processed_urls.count(js_url)) continue;
    processed_urls.insert(js_url);

    auto resp = http_.get(js_url);
    if (resp.status_code != 200 || resp.body.empty()) continue;

    // Find sources and sinks
    auto sources = find_sources(resp.body);
    auto sinks = find_sinks(resp.body);

    if (sources.empty() || sinks.empty()) continue;

    // Correlate: find source-to-sink flows
    auto flows = correlate_flows(sources, sinks, resp.body);

    for (const auto &flow : flows) {
      Finding f;
      f.type = "DOM XSS";
      f.severity = "high";
      f.url = js_url;
      f.detail = "DOM XSS: source '" + flow.source.source_type +
                 "' (line " + std::to_string(flow.source.line_number) +
                 ") flows to sink '" + flow.sink.sink_type + "' (line " +
                 std::to_string(flow.sink.line_number) + ")";
      if (!flow.function_context.empty()) {
        f.detail += " in function: " + flow.function_context;
      }
      f.param = flow.source.source_type;
      f.payload = flow.sink.sink_type;
      f.evidence = "Source: " + flow.source.context.substr(0, 100) +
                   " | Sink: " + flow.sink.context.substr(0, 100);
      f.confidence = 60;
      f.cwe_id = "CWE-79";
      f.owasp_category = "A03:2021 Injection";
      f.cvss_score = 6.1;
      findings.push_back(f);
    }

    // Limit findings per file
    if (findings.size() > 50) break;
  }

  return findings;
}

std::vector<std::string> DOMXSSDetector::find_js_urls(const CrawlResult &crawl) {
  std::vector<std::string> js_urls;
  std::set<std::string> seen;

  for (const auto &url : crawl.urls) {
    std::string lower = url;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower.find(".js") != std::string::npos &&
        lower.find(".json") == std::string::npos) {
      if (!seen.count(url)) {
        seen.insert(url);
        js_urls.push_back(url);
      }
    }
  }

  // Also check HTML pages for inline scripts
  for (const auto &url : crawl.urls) {
    std::string lower = url;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower.find(".js") == std::string::npos &&
        lower.find(".css") == std::string::npos &&
        lower.find(".png") == std::string::npos &&
        lower.find(".jpg") == std::string::npos &&
        lower.find(".svg") == std::string::npos) {
      if (!seen.count(url)) {
        seen.insert(url);
        js_urls.push_back(url); // Will extract inline scripts
      }
    }
    if (js_urls.size() > 100) break;
  }

  return js_urls;
}

std::vector<DOMXSSDetector::SourceMatch>
DOMXSSDetector::find_sources(const std::string &js_content) {
  std::vector<SourceMatch> sources;

  struct SourceDef {
    std::string name;
    std::string pattern;
  };

  static const std::vector<SourceDef> source_defs = {
      {"location.hash", R"(location\.hash)"},
      {"location.search", R"(location\.search)"},
      {"location.href", R"(location\.href)"},
      {"location.pathname", R"(location\.pathname)"},
      {"document.referrer", R"(document\.referrer)"},
      {"document.URL", R"(document\.URL)"},
      {"document.documentURI", R"(document\.documentURI)"},
      {"window.name", R"(window\.name)"},
      {"document.cookie", R"(document\.cookie)"},
      {"postMessage", R"((?:addEventListener|on)\s*\(\s*["']message["'])"},
      {"URLSearchParams", R"((?:new\s+)?URLSearchParams\s*\()"},
      {"location.hash fragment",
       R"((?:window|document)\.location\.hash)"},
      {"fragment identifier",
       R"((?:hash|fragment|anchor)\s*=\s*(?:window|document)\.location)"},
  };

  for (const auto &sdef : source_defs) {
    try {
      std::regex re(sdef.pattern);
      std::sregex_iterator it(js_content.begin(), js_content.end(), re);
      std::sregex_iterator end;

      for (; it != end; ++it) {
        SourceMatch sm;
        sm.source_type = sdef.name;

        // Calculate line number
        size_t pos = static_cast<size_t>((*it).position());
        sm.line_number = std::count(js_content.begin(),
                                    js_content.begin() + static_cast<long>(pos), '\n') + 1;

        // Get surrounding context
        size_t ctx_start = (pos > 50) ? pos - 50 : 0;
        size_t ctx_end = std::min(pos + 80, js_content.size());
        sm.context = js_content.substr(ctx_start, ctx_end - ctx_start);
        std::replace(sm.context.begin(), sm.context.end(), '\n', ' ');

        sources.push_back(sm);
      }
    } catch (const std::regex_error &) {
      continue;
    }
  }

  return sources;
}

std::vector<DOMXSSDetector::SinkMatch>
DOMXSSDetector::find_sinks(const std::string &js_content) {
  std::vector<SinkMatch> sinks;

  struct SinkDef {
    std::string name;
    std::string pattern;
  };

  static const std::vector<SinkDef> sink_defs = {
      {"innerHTML", R"(\.innerHTML\s*[=+])"},
      {"outerHTML", R"(\.outerHTML\s*[=+])"},
      {"document.write", R"(document\.write(?:ln)?\s*\()"},
      {"eval", R"(\beval\s*\()"},
      {"setTimeout-string", R"(setTimeout\s*\(\s*[^,\)]*(?:["'`]|[a-zA-Z_]\w*\s*\+))"},
      {"setInterval-string", R"(setInterval\s*\(\s*[^,\)]*(?:["'`]|[a-zA-Z_]\w*\s*\+))"},
      {"Function constructor", R"(new\s+Function\s*\()"},
      {"jQuery .html()", R"(\.\s*html\s*\(\s*[^)]+\))"},
      {"jQuery .append()", R"(\.\s*append\s*\(\s*[^)]+\))"},
      {"jQuery .prepend()", R"(\.\s*prepend\s*\(\s*[^)]+\))"},
      {"jQuery .after()", R"(\.\s*after\s*\(\s*[^)]+\))"},
      {"jQuery .before()", R"(\.\s*before\s*\(\s*[^)]+\))"},
      {"insertAdjacentHTML", R"(\.insertAdjacentHTML\s*\()"},
      {"dangerouslySetInnerHTML", R"(dangerouslySetInnerHTML)"},
      {"bypassSecurityTrust", R"(bypassSecurityTrust(?:Html|Script|Url|ResourceUrl|Style))"},
      {"v-html", R"(v-html\s*=)"},
      {"srcdoc", R"(\.srcdoc\s*=)"},
      {"document.domain", R"(document\.domain\s*=)"},
      {"location assign", R"((?:location|window\.location)\s*=)"},
      {"location.href assign", R"(location\.href\s*=)"},
  };

  for (const auto &sdef : sink_defs) {
    try {
      std::regex re(sdef.pattern);
      std::sregex_iterator it(js_content.begin(), js_content.end(), re);
      std::sregex_iterator end;

      for (; it != end; ++it) {
        SinkMatch sm;
        sm.sink_type = sdef.name;

        size_t pos = static_cast<size_t>((*it).position());
        sm.line_number = std::count(js_content.begin(),
                                    js_content.begin() + static_cast<long>(pos), '\n') + 1;

        size_t ctx_start = (pos > 50) ? pos - 50 : 0;
        size_t ctx_end = std::min(pos + 80, js_content.size());
        sm.context = js_content.substr(ctx_start, ctx_end - ctx_start);
        std::replace(sm.context.begin(), sm.context.end(), '\n', ' ');

        sinks.push_back(sm);
      }
    } catch (const std::regex_error &) {
      continue;
    }
  }

  return sinks;
}

std::vector<DOMXSSDetector::DOMXSSFlow>
DOMXSSDetector::correlate_flows(const std::vector<SourceMatch> &sources,
                                const std::vector<SinkMatch> &sinks,
                                const std::string &js_content) {
  std::vector<DOMXSSFlow> flows;

  // Strategy: if a source and sink are within the same function scope
  // (within ~50 lines of each other) and there's no sanitization between them,
  // flag it as a potential DOM XSS flow.

  const size_t MAX_LINE_DISTANCE = 50;

  for (const auto &source : sources) {
    for (const auto &sink : sinks) {
      // Source should come before or near sink
      size_t min_line = std::min(source.line_number, sink.line_number);
      size_t max_line = std::max(source.line_number, sink.line_number);

      if (max_line - min_line > MAX_LINE_DISTANCE) continue;

      // Check for sanitization between source and sink
      if (has_sanitization(js_content, source.line_number, sink.line_number))
        continue;

      // Try to identify function context
      std::string func_ctx;
      // Find the nearest function definition before the source
      static const std::regex func_re(
          R"((?:function\s+(\w+)|(\w+)\s*[=:]\s*(?:async\s+)?function|(\w+)\s*[=:]\s*(?:async\s+)?\([^)]*\)\s*=>))");

      // Extract relevant section of code
      size_t search_start = 0;
      size_t current_pos = 0;
      size_t target_line = std::min(source.line_number, sink.line_number);
      for (size_t line = 1; line < target_line && current_pos < js_content.size();
           ++line) {
        auto nl = js_content.find('\n', current_pos);
        if (nl == std::string::npos) break;
        current_pos = nl + 1;
      }
      // Look backwards for function definition (up to 500 chars)
      search_start = (current_pos > 500) ? current_pos - 500 : 0;
      std::string search_area =
          js_content.substr(search_start, current_pos - search_start);

      std::smatch fm;
      std::string::const_iterator search_begin = search_area.cbegin();
      std::string last_func;
      while (std::regex_search(search_begin, search_area.cend(), fm, func_re)) {
        for (int i = 1; i <= 3; ++i) {
          if (fm[i].matched) {
            last_func = fm[i].str();
            break;
          }
        }
        search_begin = fm.suffix().first;
      }
      func_ctx = last_func;

      DOMXSSFlow flow;
      flow.source = source;
      flow.sink = sink;
      flow.function_context = func_ctx;
      flows.push_back(flow);
    }
  }

  return flows;
}

bool DOMXSSDetector::has_sanitization(const std::string &content,
                                      size_t source_line, size_t sink_line) {
  // Extract the code between source and sink lines
  size_t min_line = std::min(source_line, sink_line);
  size_t max_line = std::max(source_line, sink_line);

  // Find line positions
  size_t start_pos = 0;
  size_t current_line = 1;
  for (; current_line < min_line && start_pos < content.size(); ++current_line) {
    auto nl = content.find('\n', start_pos);
    if (nl == std::string::npos) break;
    start_pos = nl + 1;
  }

  size_t end_pos = start_pos;
  for (; current_line <= max_line && end_pos < content.size(); ++current_line) {
    auto nl = content.find('\n', end_pos);
    if (nl == std::string::npos) {
      end_pos = content.size();
      break;
    }
    end_pos = nl + 1;
  }

  std::string between = content.substr(start_pos, end_pos - start_pos);
  std::string lower = between;
  std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

  // Check for common sanitization patterns
  if (lower.find("sanitize") != std::string::npos) return true;
  if (lower.find("escape") != std::string::npos) return true;
  if (lower.find("encode") != std::string::npos) return true;
  if (lower.find("purify") != std::string::npos) return true;
  if (lower.find("dompurify") != std::string::npos) return true;
  if (lower.find("xss") != std::string::npos) return true;
  if (lower.find("htmlentities") != std::string::npos) return true;
  if (lower.find("encodeuri") != std::string::npos) return true;
  if (lower.find("textcontent") != std::string::npos) return true;
  if (lower.find("innertext") != std::string::npos) return true;
  if (lower.find("createtextnode") != std::string::npos) return true;
  if (lower.find("validator") != std::string::npos) return true;

  return false;
}

} // namespace apex
