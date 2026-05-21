/// @file sbom.hpp
/// @brief SBOM generation (CycloneDX) and vulnerability checking via OSV.dev.
#ifndef APEX_SBOM_HPP
#define APEX_SBOM_HPP

#include "http.hpp"
#include "scanner.hpp"
#include <string>
#include <vector>

namespace apex {

/// A component in the SBOM.
struct SBOMComponent {
  std::string name;
  std::string version;
  std::string type; // library, framework, application, operating-system
  std::string purl; // Package URL (pkg:type/name@version)
};

/// A vulnerability found via OSV.dev.
struct SBOMVuln {
  std::string id;       // CVE or GHSA ID
  std::string summary;
  std::string severity; // critical, high, medium, low
  double cvss = 0.0;
  std::string component;
  std::string fixed_version;
};

/// Extract SBOM components from scan findings.
std::vector<SBOMComponent> extract_sbom(const std::vector<Finding> &findings);

/// Write CycloneDX JSON SBOM to file.
void write_sbom(const std::vector<SBOMComponent> &components,
                const std::string &target, const std::string &path);

/// Check components against OSV.dev for known vulnerabilities.
std::vector<SBOMVuln> check_osv(HttpClient &http,
                                const std::vector<SBOMComponent> &components);

} // namespace apex

#endif // APEX_SBOM_HPP
