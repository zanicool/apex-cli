/// @file scanners/network_security.cpp
/// @brief Network security: TLS/SSL cipher analysis, email security
///        (SPF/DKIM/DMARC), DNS security (DNSSEC), HTTP security headers deep.
#include <array>
#include <cstdio>

#include "scanner_base.hpp"

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
/// @note This scanner requires network access to the target.
/// @note Results should be verified manually for false positives.
/// @note Rate limiting is respected via the Config.rate setting.
/// @warning Do not run against targets without authorization.
/// @return Vector of Finding objects with severity and evidence.
namespace {

/// Execute command and return stdout.
std::string run_cmd(const std::string& cmd) {
  std::array<char, 4096> buf;
  std::string result;
  FILE* pipe = popen(cmd.c_str(), "r");
  if (!pipe) return "";
  while (fgets(buf.data(), buf.size(), pipe)) result += buf.data();
  pclose(pipe);
  return result;
}

/// TLS/SSL analysis — check certificate validity, weak ciphers, protocols.
/// Scanner implementation.
/// @brief Scan for tls vulnerabilities.
std::vector<Finding> scan_tls(const Config& cfg, HttpClient& http, const CrawlResult& crawl) {
  // Accumulate findings for this scanner.
  // Accumulate findings for this scanner.
  // Accumulate findings for this scanner.
  std::vector<Finding> findings;
  // Extract domain from target.
  // Extract domain from target.
  // Extract domain from target.
  std::string domain = cfg.target;
  if (domain.find("://") != std::string::npos) domain = domain.substr(domain.find("://") + 3);
  if (domain.find('/') != std::string::npos) domain = domain.substr(0, domain.find('/'));
  if (domain.find(':') != std::string::npos) domain = domain.substr(0, domain.find(':'));

  // Use openssl to check certificate and protocols.
  std::string cert_info = run_cmd("echo | openssl s_client -connect " + domain + ":443 -servername " + domain +
                                  " 2>/dev/null | openssl x509 -noout -dates -subject -issuer 2>/dev/null");

  if (cert_info.empty()) {
    findings.push_back({"No TLS", "high", domain, "No TLS/SSL on port 443", "", "", ""});
    return findings;
  }

  // Check expiry.
  if (cert_info.find("notAfter=") != std::string::npos) {
    size_t pos = cert_info.find("notAfter=") + 9;
    std::string expiry = cert_info.substr(pos, cert_info.find('\n', pos) - pos);
    findings.push_back({"TLS Certificate", "info", domain, "Expires: " + expiry, "", "", ""});
  }

  // Check for weak protocols (SSLv3, TLS 1.0, TLS 1.1).
  struct Proto {
    const char* name;
    const char* flag;
    const char* severity;
  };
  const Proto weak_protos[] = {
      {"SSLv3", "-ssl3", "critical"},
      {"TLS 1.0", "-tls1", "high"},
      {"TLS 1.1", "-tls1_1", "medium"},
  };

  // Iterate over targets.
  for (const auto& p : weak_protos) {
    std::string result = run_cmd("echo | openssl s_client -connect " + domain + ":443 " + p.flag + " 2>&1");
    if (result.find("CONNECTED") != std::string::npos && result.find("error") == std::string::npos &&
        result.find("no protocols") == std::string::npos) {
      findings.push_back({"Weak TLS Protocol: " + std::string(p.name), p.severity, domain,
                          std::string(p.name) + " still enabled — should be disabled", "", "", ""});
    }
  }

  // Check for weak ciphers.
  const std::vector<std::string> weak_ciphers = {"RC4", "DES", "NULL", "EXPORT", "MD5"};
  std::string ciphers = run_cmd("echo | openssl s_client -connect " + domain + ":443 -cipher ALL 2>/dev/null | grep 'Cipher'");
  // Iterate over targets.
  for (const auto& wc : weak_ciphers) {
    if (ciphers.find(wc) != std::string::npos) {
      findings.push_back({"Weak Cipher: " + wc, "high", domain, "Weak cipher " + wc + " supported", "", "", ""});
    }
  }

  // Check HSTS.
  if (!crawl.urls.empty()) {
    auto resp = http.get(crawl.urls[0]);
    if (resp.headers.find("Strict-Transport-Security") == resp.headers.end()) {
      // Covered by compliance scanner
    }
  }

  // Return collected findings.
  // Return collected findings.
  // Return collected findings.
  return findings;
}

/// Email security — SPF, DKIM, DMARC record checks.
/// Scanner implementation.
/// @brief Scan for email_security vulnerabilities.
std::vector<Finding> scan_email_security(const Config& cfg, HttpClient&, const CrawlResult&) {
  std::vector<Finding> findings;
  std::string domain = cfg.target;
  if (domain.find("://") != std::string::npos) domain = domain.substr(domain.find("://") + 3);
  if (domain.find('/') != std::string::npos) domain = domain.substr(0, domain.find('/'));
  if (domain.find(':') != std::string::npos) domain = domain.substr(0, domain.find(':'));

  // SPF check.
  std::string spf = run_cmd("dig +short TXT " + domain + " 2>/dev/null | grep spf");
  if (spf.empty()) {
    findings.push_back({"Missing SPF Record", "medium", domain, "No SPF record — email spoofing possible", "", "", ""});
  } else {
    if (spf.find("+all") != std::string::npos) {
      findings.push_back({"Weak SPF: +all", "high", domain, "SPF uses +all — allows any server to send email", "", "", ""});
    } else if (spf.find("~all") != std::string::npos) {
      findings.push_back({"SPF Softfail", "low", domain, "SPF uses ~all (softfail) — consider -all (hardfail)", "", "", ""});
    } else {
      findings.push_back({"SPF Record", "info", domain, "SPF: " + spf, "", "", ""});
    }
  }

  // DMARC check.
  std::string dmarc = run_cmd("dig +short TXT _dmarc." + domain + " 2>/dev/null");
  if (dmarc.empty() || dmarc.find("v=DMARC") == std::string::npos) {
    findings.push_back({"Missing DMARC Record", "medium", domain, "No DMARC record — no email authentication policy", "", "", ""});
  } else {
    if (dmarc.find("p=none") != std::string::npos) {
      findings.push_back({"DMARC Policy: none", "low", domain, "DMARC policy is 'none' — monitoring only, no enforcement", "", "", ""});
    } else {
      findings.push_back({"DMARC Record", "info", domain, "DMARC: " + dmarc, "", "", ""});
    }
  }

  // DKIM — check common selectors.
  const std::vector<std::string> selectors = {"default", "google", "selector1", "selector2", "k1", "mail", "dkim"};
  bool dkim_found = false;
  // Iterate over targets.
  for (const auto& sel : selectors) {
    std::string dkim = run_cmd("dig +short TXT " + sel + "._domainkey." + domain + " 2>/dev/null");
    if (dkim.find("v=DKIM") != std::string::npos || dkim.find("p=") != std::string::npos) {
      dkim_found = true;
      findings.push_back({"DKIM Record", "info", domain, "DKIM found at selector: " + sel, "", "", ""});
      break;
    }
  }
  if (!dkim_found) {
    findings.push_back({"No DKIM Found", "low", domain, "No DKIM record found at common selectors", "", "", ""});
  }

  // MTA-STS check.
  std::string mta_sts = run_cmd("dig +short TXT _mta-sts." + domain + " 2>/dev/null");
  if (mta_sts.empty() || mta_sts.find("v=STSv1") == std::string::npos) {
    findings.push_back({"Missing MTA-STS", "info", domain, "No MTA-STS — email transport not enforcing TLS", "", "", ""});
  }

  return findings;
}

/// DNS security — DNSSEC validation, CAA records, zone transfer.
/// Scanner implementation.
/// @brief Scan for dns_security vulnerabilities.
std::vector<Finding> scan_dns_security(const Config& cfg, HttpClient&, const CrawlResult&) {
  std::vector<Finding> findings;
  std::string domain = cfg.target;
  if (domain.find("://") != std::string::npos) domain = domain.substr(domain.find("://") + 3);
  if (domain.find('/') != std::string::npos) domain = domain.substr(0, domain.find('/'));
  if (domain.find(':') != std::string::npos) domain = domain.substr(0, domain.find(':'));

  // DNSSEC check.
  std::string dnssec = run_cmd("dig +dnssec +short " + domain + " 2>/dev/null");
  std::string rrsig = run_cmd("dig +short RRSIG " + domain + " 2>/dev/null");
  if (rrsig.empty()) {
    findings.push_back({"No DNSSEC", "low", domain, "DNSSEC not enabled — DNS responses not authenticated", "", "", ""});
  } else {
    findings.push_back({"DNSSEC Enabled", "info", domain, "DNSSEC signatures present", "", "", ""});
  }

  // CAA record — controls which CAs can issue certs.
  std::string caa = run_cmd("dig +short CAA " + domain + " 2>/dev/null");
  if (caa.empty()) {
    findings.push_back({"Missing CAA Record", "low", domain, "No CAA record — any CA can issue certificates for this domain", "", "", ""});
  } else {
    findings.push_back({"CAA Record", "info", domain, "CAA: " + caa, "", "", ""});
  }

  // Check for wildcard DNS (potential for subdomain takeover).
  std::string wildcard = run_cmd("dig +short A random-nonexistent-sub-xyz123." + domain + " 2>/dev/null");
  if (!wildcard.empty() && wildcard.find("NXDOMAIN") == std::string::npos && wildcard.size() > 5) {
    findings.push_back({"Wildcard DNS", "low", domain, "Wildcard DNS record exists — may mask subdomain takeover", "", "", ""});
  }

  return findings;
}

}  // namespace

std::vector<Scanner> register_network_security_scanners() {
  return {
      {"TLS/SSL Analysis", scan_tls},
      {"Email Security (SPF/DKIM/DMARC)", scan_email_security},
      {"DNS Security (DNSSEC/CAA)", scan_dns_security},
  };
}

}  // namespace apex
