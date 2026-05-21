/// @file sbom.cpp
/// @brief SBOM generation (CycloneDX) and OSV.dev vulnerability lookup.
#include "sbom.hpp"
#include <algorithm>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <regex>
#include <set>
#include <sstream>

namespace apex {

namespace {

/// Normalize product name for PURL.
std::string normalize(const std::string &name) {
  std::string out;
  for (char c : name) {
    if (std::isalnum(c) || c == '-' || c == '.') out += std::tolower(c);
    else if (c == ' ') out += '-';
  }
  return out;
}

/// Map severity string from CVSS score.
std::string severity_from_cvss(double cvss) {
  if (cvss >= 9.0) return "critical";
  if (cvss >= 7.0) return "high";
  if (cvss >= 4.0) return "medium";
  return "low";
}

/// Simple JSON string escape.
std::string json_escape(const std::string &s) {
  std::string out;
  for (char c : s) {
    if (c == '"') out += "\\\"";
    else if (c == '\\') out += "\\\\";
    else if (c == '\n') out += "\\n";
    else out += c;
  }
  return out;
}

} // namespace

std::vector<SBOMComponent> extract_sbom(const std::vector<Finding> &findings) {
  std::set<std::string> seen;
  std::vector<SBOMComponent> components;

  for (const auto &f : findings) {
    // CMS Detection findings: "Detected: Joomla v4.4.14 (OUTDATED ...)"
    if (f.type == "CMS Detection") {
      std::regex cms_re(R"re(Detected:\s+(\S+)\s+v([\d.]+))re");
      std::smatch m;
      if (std::regex_search(f.detail, m, cms_re)) {
        std::string name = m[1].str();
        std::string version = m[2].str();
        std::string key = name + "@" + version;
        if (seen.insert(key).second) {
          std::string purl = "pkg:generic/" + normalize(name) + "@" + version;
          components.push_back({name, version, "application", purl});
        }
      }
    }
    // Fingerprint findings: "Detected: X" or header values like "Server: nginx/1.24"
    if (f.type == "Fingerprint") {
      // Try to extract versioned component from evidence.
      std::regex ver_re(R"re((\w[\w. -]*?)[/: ]([\d]+\.[\d.]+))re");
      std::smatch m;
      std::string src = f.evidence.empty() ? f.detail : f.evidence;
      if (std::regex_search(src, m, ver_re)) {
        std::string name = m[1].str();
        std::string version = m[2].str();
        std::string key = name + "@" + version;
        if (seen.insert(key).second) {
          std::string purl = "pkg:generic/" + normalize(name) + "@" + version;
          components.push_back({name, version, "framework", purl});
        }
      }
    }
    // CVE findings from exploit.hpp — extract product/version.
    if (f.type == "CVE") {
      std::regex cve_ver_re(R"re((\w+)[/ ]([\d.]+))re");
      std::smatch m;
      if (std::regex_search(f.evidence, m, cve_ver_re)) {
        std::string name = m[1].str();
        std::string version = m[2].str();
        std::string key = name + "@" + version;
        if (seen.insert(key).second) {
          std::string purl = "pkg:generic/" + normalize(name) + "@" + version;
          components.push_back({name, version, "library", purl});
        }
      }
    }
  }
  return components;
}

void write_sbom(const std::vector<SBOMComponent> &components,
                const std::string &target, const std::string &path) {
  auto now = std::chrono::system_clock::now();
  auto t = std::chrono::system_clock::to_time_t(now);
  std::ostringstream ts;
  ts << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");

  std::ofstream out(path);
  out << "{\n";
  out << "  \"bomFormat\": \"CycloneDX\",\n";
  out << "  \"specVersion\": \"1.5\",\n";
  out << "  \"version\": 1,\n";
  out << "  \"metadata\": {\n";
  out << "    \"timestamp\": \"" << ts.str() << "\",\n";
  out << "    \"tools\": [{\"name\": \"apex-cli\", \"version\": \"11.0-cpp\"}],\n";
  out << "    \"component\": {\"type\": \"application\", \"name\": \""
      << json_escape(target) << "\"}\n";
  out << "  },\n";
  out << "  \"components\": [\n";

  for (size_t i = 0; i < components.size(); ++i) {
    const auto &c = components[i];
    out << "    {\n";
    out << "      \"type\": \"" << c.type << "\",\n";
    out << "      \"name\": \"" << json_escape(c.name) << "\",\n";
    out << "      \"version\": \"" << c.version << "\",\n";
    out << "      \"purl\": \"" << c.purl << "\"\n";
    out << "    }" << (i + 1 < components.size() ? "," : "") << "\n";
  }

  out << "  ]\n";
  out << "}\n";
}

std::vector<SBOMVuln> check_osv(HttpClient &http,
                                const std::vector<SBOMComponent> &components) {
  std::vector<SBOMVuln> vulns;

  for (const auto &comp : components) {
    if (comp.version.empty()) continue;

    // OSV.dev API: POST https://api.osv.dev/v1/query
    std::string body = "{\"package\":{\"name\":\"" + normalize(comp.name) +
                       "\",\"ecosystem\":\"" + "Packagist" +
                       "\"},\"version\":\"" + comp.version + "\"}";

    // Try multiple ecosystems for better coverage.
    std::vector<std::string> ecosystems = {"Packagist", "npm", "PyPI", "Maven"};

    for (const auto &eco : ecosystems) {
      std::string req = "{\"package\":{\"name\":\"" + normalize(comp.name) +
                        "\",\"ecosystem\":\"" + eco +
                        "\"},\"version\":\"" + comp.version + "\"}";

      auto resp = http.post("https://api.osv.dev/v1/query",
                            req, "application/json");

      if (resp.status_code == 200 && resp.body.size() > 10 &&
          resp.body.find("\"vulns\"") != std::string::npos) {
        // Parse vulnerabilities from response.
        std::regex id_re(R"re("id"\s*:\s*"([^"]+)")re");
        std::regex sum_re(R"re("summary"\s*:\s*"([^"]*)")re");
        std::regex score_re(R"re("score"\s*:\s*([\d.]+))re");
        std::regex fixed_re(R"re("fixed"\s*:\s*"([^"]+)")re");

        auto id_it = std::sregex_iterator(resp.body.begin(), resp.body.end(), id_re);
        auto sum_it = std::sregex_iterator(resp.body.begin(), resp.body.end(), sum_re);
        auto score_it = std::sregex_iterator(resp.body.begin(), resp.body.end(), score_re);
        auto fixed_it = std::sregex_iterator(resp.body.begin(), resp.body.end(), fixed_re);

        for (; id_it != std::sregex_iterator(); ++id_it) {
          SBOMVuln v;
          v.id = (*id_it)[1].str();
          v.component = comp.name + "@" + comp.version;

          if (sum_it != std::sregex_iterator()) {
            v.summary = (*sum_it)[1].str();
            ++sum_it;
          }
          if (score_it != std::sregex_iterator()) {
            v.cvss = std::stod((*score_it)[1].str());
            v.severity = severity_from_cvss(v.cvss);
            ++score_it;
          } else {
            v.severity = "medium";
          }
          if (fixed_it != std::sregex_iterator()) {
            v.fixed_version = (*fixed_it)[1].str();
            ++fixed_it;
          }

          vulns.push_back(v);
        }

        break; // Found results in this ecosystem, stop trying others.
      }
    }
  }
  return vulns;
}

} // namespace apex
