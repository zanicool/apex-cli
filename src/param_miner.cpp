/// @file param_miner.cpp
/// @brief Hidden Parameter Discovery Engine (like Burp Param Miner).
#include "param_miner.hpp"

#include <algorithm>
#include <regex>
#include <set>
#include <sstream>

namespace apex {

std::vector<std::string> ParamMiner::get_param_wordlist() {
  return {
      "debug",       "test",        "admin",       "internal",    "verbose",
      "dev",         "source",      "config",      "token",       "key",
      "secret",      "password",    "api_key",     "callback",    "redirect",
      "next",        "url",         "file",        "path",        "template",
      "format",      "output",      "mode",        "action",      "method",
      "type",        "id",          "user",        "username",    "email",
      "login",       "pass",        "passwd",      "pwd",         "auth",
      "session",     "cookie",      "jwt",         "bearer",      "access_token",
      "refresh_token", "client_id", "client_secret", "grant_type", "scope",
      "state",       "nonce",       "code",        "response_type", "redirect_uri",
      "return_url",  "continue",    "goto",        "target",      "dest",
      "destination", "redir",       "return",      "returnTo",    "return_to",
      "back",        "backurl",     "from",        "ref",         "referrer",
      "source_url",  "origin",      "page",        "p",           "q",
      "query",       "search",      "s",           "keyword",     "term",
      "filter",      "sort",        "order",       "limit",       "offset",
      "skip",        "take",        "count",       "size",        "per_page",
      "page_size",   "pageSize",    "pageNum",     "num",         "start",
      "end",         "from_date",   "to_date",     "date",        "time",
      "timestamp",   "ts",          "version",     "v",           "ver",
      "lang",        "language",    "locale",      "country",     "region",
      "currency",    "tz",          "timezone",    "encoding",    "charset",
      "content_type","accept",      "format_type", "json",        "xml",
      "csv",         "yaml",        "html",        "text",        "raw",
      "pretty",      "indent",      "compact",     "minify",      "compress",
      "gzip",        "deflate",     "cache",       "no_cache",    "nocache",
      "refresh",     "reload",      "force",       "retry",       "timeout",
      "delay",       "wait",        "sleep",       "interval",    "rate",
      "throttle",    "burst",       "max",         "min",         "default",
      "fallback",    "override",    "custom",      "extra",       "additional",
      "include",     "exclude",     "fields",      "select",      "expand",
      "embed",       "populate",    "join",        "with",        "without",
      "only",        "except",      "ignore",      "skip_validation", "validate",
      "verify",      "check",       "confirm",     "approve",     "deny",
      "allow",       "block",       "ban",         "unban",       "enable",
      "disable",     "activate",    "deactivate",  "suspend",     "resume",
      "start_action","stop",        "pause",       "cancel",      "abort",
      "reset",       "clear",       "flush",       "purge",       "delete",
      "remove",      "destroy",     "create",      "add",         "insert",
      "update",      "modify",      "edit",        "change",      "set",
      "put",         "patch",       "replace",     "merge",       "sync",
      "import",      "export",      "upload",      "download",    "fetch",
      "pull",        "push",        "send",        "receive",     "get",
      "post_param",  "list",        "show",        "view",        "read",
      "write",       "execute",     "run",         "invoke",      "call",
      "trigger",     "fire",        "emit",        "dispatch",    "publish",
      "subscribe",   "listen",      "watch",       "observe",     "monitor",
      "track",       "log",         "audit",       "trace",       "profile",
      "benchmark",   "perf",        "metrics",     "stats",       "status",
      "health",      "info",        "about",       "help",        "usage",
      "docs",        "documentation","api",        "rest",        "graphql",
      "grpc",        "soap",        "rpc",         "websocket",   "ws",
      "sse",         "stream",      "event",       "hook",        "webhook",
      "notify",      "alert",       "alarm",       "warning",     "error",
      "exception",   "fault",       "failure",     "success",     "ok",
      "true",        "false",       "yes",         "no",          "on",
      "off",         "enabled",     "disabled",    "active",      "inactive",
      "public",      "private",     "protected",   "hidden",      "visible",
      "show_hidden", "show_deleted","include_deleted", "soft_delete","hard_delete",
      "recursive",   "deep",        "shallow",     "flat",        "nested",
      "tree",        "hierarchy",   "parent",      "child",       "children",
      "root",        "leaf",        "node",        "edge",        "graph",
      "network",     "cluster",     "group",       "category",    "tag",
      "label",       "name",        "title",       "description", "summary",
      "body",        "content",     "text",        "message",     "comment",
      "note",        "remark",      "annotation",  "metadata",    "meta",
      "data",        "payload",     "input",       "output_param","result",
      "response",    "request",     "headers",     "params",      "args",
      "arguments",   "options",     "settings",    "preferences", "configuration",
      "env",         "environment", "context",     "namespace",   "prefix",
      "suffix",      "separator",   "delimiter",   "escape",      "quote",
      "wrap",        "trim",        "strip",       "clean",       "sanitize",
      "normalize",   "transform",   "convert",     "parse",       "serialize",
      "deserialize", "encode",      "decode",      "encrypt",     "decrypt",
      "sign",        "hash",        "digest",      "checksum",    "fingerprint",
      "uuid",        "guid",        "random",      "seed",        "salt",
  };
}

ParamMiner::BaselineResponse
ParamMiner::capture_baseline(HttpClient &http, const std::string &url) {
  auto resp = http.get(url);
  BaselineResponse bl;
  bl.status_code = resp.status_code;
  bl.body_size = resp.body.size();
  bl.content_type = "";
  bl.headers = resp.headers;
  for (const auto &[k, v] : resp.headers) {
    std::string k_lower = k;
    std::transform(k_lower.begin(), k_lower.end(), k_lower.begin(), ::tolower);
    if (k_lower == "content-type")
      bl.content_type = v;
  }
  return bl;
}

bool ParamMiner::response_differs(const BaselineResponse &baseline,
                                   const Response &resp) {
  // Different status code
  if (resp.status_code != baseline.status_code)
    return true;

  // Significant body size difference (>10% or >100 bytes)
  int size_diff = static_cast<int>(resp.body.size()) -
                  static_cast<int>(baseline.body_size);
  if (size_diff < 0)
    size_diff = -size_diff;
  if (size_diff > 100 ||
      (baseline.body_size > 0 &&
       static_cast<double>(size_diff) / baseline.body_size > 0.1))
    return true;

  // New headers appeared
  for (const auto &[k, v] : resp.headers) {
    if (baseline.headers.find(k) == baseline.headers.end())
      return true;
  }

  return false;
}

std::vector<Finding> ParamMiner::mine(const CrawlResult &crawl,
                                      HttpClient &http, const Config &cfg) {
  std::vector<Finding> findings;

  std::set<std::string> tested;
  int max_urls = cfg.quick ? 5 : 20;
  int url_count = 0;

  for (const auto &url : crawl.urls) {
    if (url_count >= max_urls)
      break;
    if (tested.count(url))
      continue;
    tested.insert(url);
    url_count++;

    auto f1 = mine_query_params(url, http);
    findings.insert(findings.end(), f1.begin(), f1.end());

    auto f2 = mine_json_params(url, http);
    findings.insert(findings.end(), f2.begin(), f2.end());

    auto f3 = mine_header_params(url, http);
    findings.insert(findings.end(), f3.begin(), f3.end());

    if (cfg.quick && findings.size() >= 10)
      break;
  }

  return findings;
}

std::vector<Finding> ParamMiner::mine_query_params(const std::string &url,
                                                   HttpClient &http) {
  std::vector<Finding> findings;
  auto wordlist = get_param_wordlist();
  auto baseline = capture_baseline(http, url);

  if (baseline.status_code == 0)
    return findings;

  // Batch params to reduce requests (test 10 at a time)
  size_t batch_size = 10;
  for (size_t i = 0; i < wordlist.size(); i += batch_size) {
    std::string test_url = url;
    std::string separator = (url.find('?') != std::string::npos) ? "&" : "?";
    std::vector<std::string> batch_params;

    for (size_t j = i; j < std::min(i + batch_size, wordlist.size()); ++j) {
      if (j == i) {
        test_url += separator + wordlist[j] + "=apex_test";
      } else {
        test_url += "&" + wordlist[j] + "=apex_test";
      }
      batch_params.push_back(wordlist[j]);
    }

    auto resp = http.get(test_url);
    if (response_differs(baseline, resp)) {
      // Narrow down which specific param caused the difference
      for (const auto &param : batch_params) {
        std::string single_url = url;
        std::string sep =
            (url.find('?') != std::string::npos) ? "&" : "?";
        single_url += sep + param + "=apex_test";

        auto single_resp = http.get(single_url);
        if (response_differs(baseline, single_resp)) {
          Finding f;
          f.type = "hidden-parameter-discovered";
          f.severity = "medium";
          f.url = single_url;
          f.detail = "Hidden parameter '" + param +
                     "' causes response change";
          f.param = param;
          f.payload = param + "=apex_test";

          std::string evidence;
          if (single_resp.status_code != baseline.status_code) {
            evidence = "Status: " + std::to_string(baseline.status_code) +
                       " → " + std::to_string(single_resp.status_code);
          } else {
            evidence =
                "Size: " + std::to_string(baseline.body_size) + " → " +
                std::to_string(single_resp.body.size());
          }
          f.evidence = evidence;
          f.confidence = 70;
          f.cwe_id = "CWE-200";
          f.owasp_category = "A05:2021 Security Misconfiguration";
          f.cvss_score = 5.3;

          // Upgrade severity for sensitive params
          std::vector<std::string> sensitive = {"debug",  "admin",  "internal",
                                                "secret", "config", "password",
                                                "token",  "key"};
          for (const auto &s : sensitive) {
            if (param == s) {
              f.severity = "high";
              f.cvss_score = 7.5;
              f.confidence = 80;
              break;
            }
          }

          findings.push_back(f);
        }
      }
    }

    if (findings.size() >= 20)
      break;
  }

  return findings;
}

std::vector<Finding> ParamMiner::mine_json_params(const std::string &url,
                                                  HttpClient &http) {
  std::vector<Finding> findings;

  // Test POST with JSON bodies containing hidden fields
  auto baseline = http.post(url, "{}", "application/json");
  if (baseline.status_code == 0 || baseline.status_code == 404 ||
      baseline.status_code == 405)
    return findings;

  std::vector<std::string> sensitive_json_params = {
      "admin",     "is_admin",   "role",       "privilege",
      "debug",     "internal",   "test",       "verbose",
      "password",  "token",      "secret",     "api_key",
      "access",    "permissions","superuser",  "staff",
      "verified",  "approved",   "active",     "deleted",
  };

  for (const auto &param : sensitive_json_params) {
    std::string json_body = "{\"" + param + "\": true}";
    auto resp = http.post(url, json_body, "application/json");

    if (resp.status_code != baseline.status_code ||
        (resp.body.size() != baseline.body.size() &&
         static_cast<int>(resp.body.size()) -
                 static_cast<int>(baseline.body.size()) >
             50)) {
      Finding f;
      f.type = "hidden-json-parameter";
      f.severity = "high";
      f.url = url;
      f.detail = "Hidden JSON parameter '" + param +
                 "' accepted and causes response change";
      f.param = param;
      f.payload = json_body;
      f.evidence = "Baseline status: " +
                   std::to_string(baseline.status_code) + " (size: " +
                   std::to_string(baseline.body.size()) + ") → With param: " +
                   std::to_string(resp.status_code) + " (size: " +
                   std::to_string(resp.body.size()) + ")";
      f.confidence = 75;
      f.cwe_id = "CWE-915";
      f.owasp_category = "A04:2021 Insecure Design";
      f.cvss_score = 7.5;
      findings.push_back(f);
    }

    if (findings.size() >= 10)
      break;
  }

  return findings;
}

std::vector<Finding> ParamMiner::mine_header_params(const std::string &url,
                                                    HttpClient &http) {
  std::vector<Finding> findings;

  auto baseline = http.get(url);
  if (baseline.status_code == 0)
    return findings;

  // Custom headers that might unlock hidden functionality
  std::vector<std::pair<std::string, std::string>> test_headers = {
      {"X-Debug", "1"},
      {"X-Debug-Mode", "true"},
      {"X-Internal", "true"},
      {"X-Test", "1"},
      {"X-Dev", "1"},
      {"X-Custom-Auth", "admin"},
      {"X-Api-Version", "internal"},
      {"X-Feature-Flag", "all"},
      {"X-Verbose", "true"},
      {"X-Source", "internal"},
      {"X-Environment", "development"},
      {"X-Admin", "true"},
      {"X-Bypass-Cache", "1"},
      {"X-No-Rate-Limit", "true"},
      {"X-Request-Id", "../../../../etc/passwd"},
  };

  for (const auto &[header, value] : test_headers) {
    std::vector<std::pair<std::string, std::string>> hdrs = {{header, value}};
    auto resp = http.get(url, hdrs);

    // Check for response differences
    if (resp.status_code != baseline.status_code ||
        resp.body.size() > baseline.body.size() + 100) {
      Finding f;
      f.type = "hidden-header-parameter";
      f.severity = "medium";
      f.url = url;
      f.detail =
          "Custom header '" + header + ": " + value +
          "' causes response change — possible hidden functionality";
      f.param = header;
      f.payload = header + ": " + value;
      f.evidence = "Baseline: " + std::to_string(baseline.status_code) +
                   " (size: " + std::to_string(baseline.body.size()) +
                   ") → With header: " + std::to_string(resp.status_code) +
                   " (size: " + std::to_string(resp.body.size()) + ")";
      f.confidence = 65;
      f.cwe_id = "CWE-200";
      f.owasp_category = "A05:2021 Security Misconfiguration";
      f.cvss_score = 5.3;
      findings.push_back(f);
    }

    if (findings.size() >= 5)
      break;
  }

  return findings;
}

} // namespace apex
