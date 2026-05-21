/// @file scanners/infrastructure.cpp
/// @brief Infrastructure: subdomain takeover, S3 bucket misconfig, DNS zone
///        transfer, virtual host fuzzing.
#include "scanner_base.hpp"
#include <arpa/inet.h>
#include <cstring>
#include <netdb.h>
#include <sys/socket.h>
#include <unistd.h>

namespace apex {
namespace {

/// Subdomain takeover — detect dangling DNS records.
std::vector<Finding> scan_subdomain_takeover(const Config &, HttpClient &http,
                                             const CrawlResult &crawl) {
  std::vector<Finding> findings;
  const std::vector<std::pair<std::string, std::string>> fingerprints = {
      {"There isn't a GitHub Pages site here", "GitHub Pages"},
      {"NoSuchBucket", "AWS S3"},
      {"Heroku | No such app", "Heroku"},
      {"Repository not found", "Bitbucket"},
      {"Sorry, this shop is currently unavailable", "Shopify"},
      {"The feed has not been found", "Feedpress"},
      {"project not found", "Surge.sh"},
      {"This UserVoice subdomain is currently available", "UserVoice"}};

  for (const auto &url : crawl.urls) {
    auto resp = http.get(url);
    for (const auto &[fp, service] : fingerprints) {
      if (resp.body.find(fp) != std::string::npos) {
        findings.push_back({"Subdomain Takeover", "high", url,
                            "Potential " + service + " takeover", "", "", fp});
      }
    }
  }
  return findings;
}

/// S3 bucket misconfiguration.
std::vector<Finding> scan_s3_buckets(const Config &, HttpClient &http,
                                     const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  // Extract domain for bucket name guessing.
  std::string base = base_url_from(crawl.urls[0]);
  size_t start = base.find("://") + 3;
  std::string domain = base.substr(start);
  size_t dot = domain.find('.');
  std::string prefix = (dot != std::string::npos) ? domain.substr(0, dot) : domain;

  const std::vector<std::string> suffixes = {
      "", "-assets", "-backup", "-dev", "-staging", "-prod", "-media",
      "-uploads", "-static", "-data", "-logs"};

  for (const auto &suffix : suffixes) {
    std::string bucket = prefix + suffix;
    std::string url = "https://" + bucket + ".s3.amazonaws.com/";
    auto resp = http.get(url);
    if (resp.status_code == 200 &&
        resp.body.find("<ListBucketResult") != std::string::npos) {
      findings.push_back({"S3 Bucket", "high", url,
                          "Public S3 bucket listing: " + bucket, "", "", ""});
    } else if (resp.status_code == 403) {
      findings.push_back({"S3 Bucket", "info", url,
                          "S3 bucket exists (no listing): " + bucket,
                          "", "", ""});
    }
  }
  return findings;
}

/// DNS zone transfer attempt.
std::vector<Finding> scan_dns_zone_transfer(const Config &cfg, HttpClient &,
                                            const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  std::string base = base_url_from(crawl.urls[0]);
  size_t start = base.find("://") + 3;
  std::string domain = base.substr(start);

  // Try AXFR via dig command.
  std::string cmd = "dig @ns1." + domain + " " + domain +
                    " AXFR +short +time=5 2>/dev/null | head -5";
  FILE *pipe = popen(cmd.c_str(), "r");
  if (!pipe) return findings;

  std::string output;
  char buf[256];
  while (fgets(buf, sizeof(buf), pipe)) output += buf;
  pclose(pipe);

  if (!output.empty() && output.find("Transfer failed") == std::string::npos &&
      output.find("timed out") == std::string::npos) {
    findings.push_back({"DNS Zone Transfer", "high", domain,
                        "Zone transfer possible", "", "", output.substr(0, 200)});
  }
  return findings;
}

/// Virtual host fuzzing — discover hidden vhosts.
std::vector<Finding> scan_vhost_fuzzing(const Config &, HttpClient &http,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Get baseline response.
  auto baseline = http.get(base + "/");

  const std::vector<std::string> prefixes = {
      "admin", "dev", "staging", "test", "internal", "api", "mail",
      "vpn", "portal", "intranet", "jenkins", "gitlab", "jira"};

  size_t start = base.find("://") + 3;
  std::string domain = base.substr(start);

  for (const auto &prefix : prefixes) {
    std::string vhost = prefix + "." + domain;
    auto resp = http.get(base + "/", {{"Host", vhost}});
    if (resp.status_code == 200 && resp.body != baseline.body &&
        resp.body.size() > 100) {
      findings.push_back({"VHost Discovery", "info", base,
                          "Different response for Host: " + vhost,
                          "", vhost, ""});
    }
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_infrastructure_scanners() {
  return {
      {"Subdomain Takeover", scan_subdomain_takeover},
      {"S3 Buckets", scan_s3_buckets},
      {"DNS Zone Transfer", scan_dns_zone_transfer},
      {"VHost Fuzzing", scan_vhost_fuzzing},
  };
}

} // namespace apex
