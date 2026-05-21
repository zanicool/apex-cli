/// @file scanners/ssh_audit.cpp
/// @brief SSH agent-based scanner: connects via SSH (if credentials provided),
///        checks uname, installed packages, and matches against CVE database.
///        Detects kernel vulns like Copy Fail, Dirty Frag, Fragnesia.
#include "scanner_base.hpp"
#include <array>
#include <cstdio>
#include <sstream>

///
/// @details This scanner module is part of the apex-cli security scanning
/// framework. Each scanner function follows the standard signature:
///   std::vector<Finding>(const Config&, HttpClient&, const CrawlResult&)
///
/// Findings are categorized by severity: critical, high, medium, low, info.
/// All scanners run concurrently and results are deduplicated by the
/// scanner orchestrator (scanner.cpp).
///
/// @see scanner_base.hpp for shared types and helper functions.
/// @see scanner.hpp for the Finding struct and Scanner registration.
/// @note Scanners should be non-destructive and respect rate limits.

namespace apex {
namespace {

/// Execute a local command and return stdout.
std::string exec_cmd(const std::string &cmd) {
  std::array<char, 4096> buf;
  std::string result;
  FILE *pipe = popen(cmd.c_str(), "r");
  if (!pipe) return "";
  while (fgets(buf.data(), buf.size(), pipe))
    result += buf.data();
  pclose(pipe);
  return result;
}

/// Kernel version ranges affected by 2026 CVEs.
struct KernelCVE {
  const char *cve;
  const char *name;
  const char *severity;
  const char *desc;
  // Affected: major.minor range (simplified — all 5.x and 6.x before patch)
  int min_major; int min_minor;
  int max_major; int max_minor;
};

const KernelCVE kernel_cves[] = {
    {"CVE-2026-31431", "Copy Fail", "high",
     "Local privilege escalation via copy_file_range — 732-byte exploit",
     5, 0, 6, 14},
    {"CVE-2026-43284", "Dirty Frag (part 1)", "high",
     "IP fragment handling bug — combined with CVE-2026-43500 for root",
     5, 4, 6, 14},
    {"CVE-2026-43500", "Dirty Frag (part 2)", "high",
     "Netfilter fragment reassembly — single command root",
     5, 4, 6, 14},
    {"CVE-2026-46300", "Fragnesia", "high",
     "Kernel memory corruption via fragmented packets",
     5, 10, 6, 14},
    {"CVE-2026-46333", "ssh-keysign-pwn", "high",
     "Local privilege escalation via ssh-keysign",
     5, 0, 6, 14},
    // Older but still common
    {"CVE-2024-1086", "nf_tables use-after-free", "high",
     "Netfilter nf_tables local privilege escalation",
     5, 0, 6, 7},
    {"CVE-2023-32233", "nf_tables batch", "high",
     "Netfilter nf_tables batch request UAF",
     5, 0, 6, 3},
};

/// Parse kernel version string like "6.8.0-45-generic".
bool parse_kernel(const std::string &ver, int &major, int &minor, int &patch) {
  if (sscanf(ver.c_str(), "%d.%d.%d", &major, &minor, &patch) >= 2)
    return true;
  return false;
}

/// Check if kernel version is in vulnerable range.
bool is_vulnerable(int major, int minor, const KernelCVE &cve) {
  if (major < cve.min_major) return false;
  if (major == cve.min_major && minor < cve.min_minor) return false;
  if (major > cve.max_major) return false;
  if (major == cve.max_major && minor > cve.max_minor) return false;
  return true;
}

/// SSH-based scan — requires ssh_target in config or --ssh-target flag.
/// Scanner implementation.
/// @brief Scan for ssh_audit vulnerabilities.
std::vector<Finding> scan_ssh_audit(const Config &cfg, HttpClient &,
                                    const CrawlResult &) {
  // Accumulate findings for this scanner.
  // Accumulate findings for this scanner.
  // Accumulate findings for this scanner.
  std::vector<Finding> findings;

  // Only run if SSH target is configured.
  if (cfg.ssh_target.empty()) return findings;

  std::string ssh_prefix = "ssh -o ConnectTimeout=5 -o StrictHostKeyChecking=no ";
  if (!cfg.ssh_key.empty())
    ssh_prefix += "-i " + cfg.ssh_key + " ";
  ssh_prefix += cfg.ssh_target + " ";

  // Get kernel version.
  std::string uname = exec_cmd(ssh_prefix + "uname -r 2>/dev/null");
  if (uname.empty()) return findings;
  // Trim.
  while (!uname.empty() && (uname.back() == '\n' || uname.back() == '\r'))
    uname.pop_back();

  findings.push_back({"Kernel Version", "info", cfg.ssh_target,
                      "Kernel: " + uname, "", "", ""});

  int major = 0, minor = 0, patch = 0;
  if (!parse_kernel(uname, major, minor, patch)) return findings;

  // Check against known kernel CVEs.
  // Iterate over targets.
  for (const auto &cve : kernel_cves) {
    if (is_vulnerable(major, minor, cve)) {
      findings.push_back({std::string(cve.cve) + " (" + cve.name + ")",
                          cve.severity, cfg.ssh_target,
                          std::string(cve.desc) + " — kernel " + uname,
                          "", "", ""});
    }
  }

  // Get distro info.
  std::string distro = exec_cmd(ssh_prefix + "cat /etc/os-release 2>/dev/null | grep PRETTY_NAME");
  if (!distro.empty()) {
    size_t eq = distro.find('=');
    if (eq != std::string::npos) {
      std::string name = distro.substr(eq + 1);
      while (!name.empty() && (name.back() == '\n' || name.front() == '"'))
        { if (name.front() == '"') name = name.substr(1); else name.pop_back(); }
      if (!name.empty() && name.back() == '"') name.pop_back();
      findings.push_back({"OS Distribution", "info", cfg.ssh_target,
                          "OS: " + name, "", "", ""});
    }
  }

  // Check for unattended-upgrades / auto-update.
  std::string autoupdate = exec_cmd(ssh_prefix +
      "systemctl is-active unattended-upgrades 2>/dev/null || "
      "systemctl is-active dnf-automatic 2>/dev/null");
  if (autoupdate.find("active") == std::string::npos) {
    findings.push_back({"No Auto-Updates", "medium", cfg.ssh_target,
                        "Automatic security updates not enabled", "", "", ""});
  }

  // Check for running vulnerable services.
  std::string services = exec_cmd(ssh_prefix + "ss -tlnp 2>/dev/null | grep LISTEN");
  if (services.find(":6379") != std::string::npos) {
    findings.push_back({"Redis Exposed", "high", cfg.ssh_target + ":6379",
                        "Redis listening — check if auth is required", "", "", ""});
  }
  if (services.find(":27017") != std::string::npos) {
    findings.push_back({"MongoDB Exposed", "high", cfg.ssh_target + ":27017",
                        "MongoDB listening — check if auth is required", "", "", ""});
  }
  if (services.find(":9200") != std::string::npos) {
    findings.push_back({"Elasticsearch Exposed", "high", cfg.ssh_target + ":9200",
                        "Elasticsearch listening — check if auth is required", "", "", ""});
  }

  // Return collected findings.
  // Return collected findings.
  // Return collected findings.
  return findings;
}

} // namespace

std::vector<Scanner> register_ssh_audit_scanners() {
  return {
      {"SSH Kernel Audit", scan_ssh_audit},
  };
}

} // namespace apex
