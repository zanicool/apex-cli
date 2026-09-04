/// @file scanners/nuclei.cpp
/// @brief Nuclei integration — runs the Nuclei engine (MIT, ProjectDiscovery)
///        against the URLs discovered by our own crawler and parses its JSONL
///        output back into the unified Finding model.
///
/// This turns Nuclei's large community template library (thousands of real
/// CVE / misconfiguration checks) into a first-class source of findings,
/// rather than duplicating that coverage by hand. Nuclei is invoked through
/// the safe argv-based run_command() (no shell), and only when the binary is
/// actually present — otherwise the scanner is a no-op.
#include "scanner_base.hpp"
#include "../proc.hpp"

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <set>

namespace apex {
namespace {

/// Extract a JSON string value for `"key":"..."` starting the search at `from`.
/// Minimal, dependency-free — matches the parsing style used elsewhere in the
/// codebase. Returns empty string if not found within a small window.
std::string json_str(const std::string &line, const std::string &key) {
  std::string needle = "\"" + key + "\"";
  size_t k = line.find(needle);
  if (k == std::string::npos) return "";
  size_t colon = line.find(':', k + needle.size());
  if (colon == std::string::npos) return "";
  // Skip whitespace.
  size_t i = colon + 1;
  while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) ++i;
  if (i >= line.size() || line[i] != '"') return "";
  size_t start = i + 1;
  std::string out;
  for (size_t j = start; j < line.size(); ++j) {
    char c = line[j];
    if (c == '\\' && j + 1 < line.size()) { out += line[j + 1]; ++j; continue; }
    if (c == '"') break;
    out += c;
  }
  return out;
}

/// Extract a nested JSON string, e.g. info.severity -> look for "severity".
/// Nuclei's JSONL nests severity under "info", but the key name is unique
/// enough that a direct search is reliable here.
std::string json_nested(const std::string &line, const std::string &key) {
  return json_str(line, key);
}

/// Map a nuclei severity string to our severity vocabulary.
std::string map_severity(const std::string &nuclei_sev) {
  if (nuclei_sev == "critical") return "critical";
  if (nuclei_sev == "high") return "high";
  if (nuclei_sev == "medium") return "medium";
  if (nuclei_sev == "low") return "low";
  return "info"; // info / unknown
}

/// Nuclei engine scanner.
std::vector<Finding> scan_nuclei_engine(const Config &cfg, HttpClient &,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (cfg.dry_run) return findings;
  if (!command_exists("nuclei")) return findings;

  // Build the target list from unique host ROOTS only. Nuclei's exposure /
  // config / takeover templates append their own known paths (e.g.
  // "/.git/config") to each target, so a single root per host is sufficient —
  // and critical for speed: nuclei loads a large template set per target, so
  // feeding it every crawled path would multiply runtime by 10x+ and blow the
  // timeout (which previously yielded zero results).
  auto host_root = [](const std::string &url) -> std::string {
    auto scheme = url.find("://");
    if (scheme == std::string::npos) return "";
    auto slash = url.find('/', scheme + 3);
    return slash == std::string::npos ? url : url.substr(0, slash);
  };

  std::set<std::string> targets;
  for (const auto &u : crawl.urls) {
    std::string root = host_root(u);
    if (!root.empty()) targets.insert(root);
  }
  if (targets.empty() && !cfg.target.empty()) {
    std::string t = cfg.target;
    if (t.find("://") == std::string::npos) t = "https://" + t;
    targets.insert(host_root(t).empty() ? t : host_root(t));
  }
  if (targets.empty()) return findings;

  // Write targets to a temp file for nuclei -list.
  std::string list_path =
      (std::filesystem::temp_directory_path() / "apex_nuclei_targets.txt")
          .string();
  {
    std::ofstream out(list_path);
    if (!out.is_open()) return findings;
    for (const auto &t : targets) out << t << "\n";
  }

  std::string out_path =
      (std::filesystem::temp_directory_path() / "apex_nuclei_out.jsonl")
          .string();
  std::remove(out_path.c_str());

  // Invoke nuclei via safe argv exec. Scope to high-signal template tags
  // (exposures, misconfig, CVEs, takeovers, default logins). NOTE: we do not
  // combine this with -severity — in testing, adding a severity filter on top
  // of tag scoping suppressed valid matches (e.g. the medium git-config
  // exposure). Severity is instead read from each result and mapped below.
  std::vector<std::string> argv = {
      "nuclei",  "-list",    list_path,
      "-jsonl",  "-output",  out_path,
      "-tags",   "exposure,config,default-login,takeover",
      "-silent", "-no-color",
      "-timeout", std::to_string(cfg.timeout > 0 ? cfg.timeout : 10)};
  if (cfg.rate > 0) {
    argv.push_back("-rate-limit");
    argv.push_back(std::to_string(static_cast<int>(1.0 / cfg.rate)));
  }
  if (!cfg.proxy.empty()) {
    argv.push_back("-proxy");
    argv.push_back(cfg.proxy);
  }

  // Nuclei can be slow; give it a generous but bounded timeout.
  run_command(argv, /*timeout_secs=*/600, /*capture_stdout=*/false);

  // Parse JSONL results.
  std::ifstream in(out_path);
  if (!in.is_open()) return findings;
  std::string line;
  while (std::getline(in, line)) {
    if (line.empty()) continue;
    std::string template_id = json_str(line, "template-id");
    std::string severity = map_severity(json_nested(line, "severity"));
    std::string matched = json_str(line, "matched-at");
    if (matched.empty()) matched = json_str(line, "host");
    std::string name = json_nested(line, "name");
    std::string matcher = json_str(line, "matcher-name");

    if (template_id.empty() && name.empty()) continue;

    Finding f;
    f.type = "Nuclei: " + (name.empty() ? template_id : name);
    f.severity = severity;
    f.url = matched;
    f.detail = "Nuclei template " + template_id +
               (matcher.empty() ? "" : " (matcher: " + matcher + ")");
    f.payload = template_id;         // template id doubles as the "payload"
    f.evidence = matcher.empty() ? template_id : matcher; // concrete evidence
    findings.push_back(std::move(f));
  }

  std::remove(list_path.c_str());
  std::remove(out_path.c_str());
  return findings;
}

} // namespace

std::vector<Scanner> register_nuclei_scanners() {
  return {
      {"Nuclei Engine", scan_nuclei_engine},
  };
}

} // namespace apex
