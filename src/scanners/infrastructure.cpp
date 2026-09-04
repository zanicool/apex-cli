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
    // Only a genuinely PUBLIC, listable bucket is a finding — and we capture
    // the listing as evidence. A 403 merely means "a bucket with this guessed
    // name exists somewhere" (almost always true for generic names like the
    // target prefix) and says nothing about the target — reporting it produced
    // a burst of evidence-less false positives, so that branch was removed.
    if (resp.status_code == 200 &&
        resp.body.find("<ListBucketResult") != std::string::npos) {
      findings.push_back({"S3 Bucket", "high", url,
                          "Public S3 bucket listing: " + bucket, "", "",
                          resp.body.substr(0, 200)});
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

/// Open port scan — check common service ports.
std::vector<Finding> scan_open_ports(const Config &cfg, HttpClient &,
                                     const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);
  size_t start = base.find("://") + 3;
  std::string host = base.substr(start);

  const int ports[] = {21, 22, 23, 25, 3306, 5432, 6379, 8080, 8443, 9200};
  for (int port : ports) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) continue;
    struct timeval tv = {2, 0};
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    struct hostent *he = gethostbyname(host.c_str());
    if (!he) { close(sock); continue; }
    memcpy(&addr.sin_addr, he->h_addr, he->h_length);
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == 0) {
      findings.push_back({"Open Port", "info", host + ":" + std::to_string(port),
                          "Port " + std::to_string(port) + " open", "", "", ""});
    }
    close(sock);
  }
  return findings;
}

/// DNS Rebinding — check if target is vulnerable to DNS rebinding.
std::vector<Finding> scan_dns_rebinding(const Config &, HttpClient &http,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  auto resp = http.get(crawl.urls[0]);
  // Sending our OWN host back proves nothing — every single-host app returns
  // the same body. Real DNS-rebinding relevance requires the server to also
  // serve identical content for an ARBITRARY attacker-controlled Host (i.e. no
  // Host allow-listing / vhost validation at all). Even then this is only an
  // observation: exploiting DNS rebinding needs a victim browser + TTL trick
  // we cannot perform here, so it is reported as INFO (never a Probable vuln).
  auto attacker = http.get(crawl.urls[0], {{"Host", "attacker.example.com"}});
  bool no_host_validation =
      attacker.status_code == resp.status_code &&
      attacker.status_code == 200 && attacker.body == resp.body;
  if (no_host_validation) {
    findings.push_back(
        {"DNS Rebinding", "info", crawl.urls[0],
         "No Host-header validation (arbitrary Host served identical content) "
         "— DNS-rebinding precondition; not remotely confirmable",
         "", "Host: attacker.example.com",
         "arbitrary Host returned identical 200 response"});
  }
  return findings;
}

/// Subdomain Permutation — find related subdomains via common prefixes.
std::vector<Finding> scan_subdomain_permutation(const Config &, HttpClient &http,
                                                const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);
  size_t start = base.find("://") + 3;
  std::string domain = base.substr(start);

  const std::vector<std::string> prefixes = {
      "staging", "dev", "test", "uat", "beta", "old", "new", "backup"};
  for (const auto &pre : prefixes) {
    std::string url = "https://" + pre + "." + domain + "/";
    auto resp = http.get(url);
    if (resp.status_code == 200 && resp.body.size() > 100) {
      findings.push_back({"Subdomain Permutation", "info", url,
                          "Subdomain " + pre + "." + domain + " is live",
                          "", "", ""});
    }
  }
  return findings;
}

/// Staging Exposure — find staging/test environments.
std::vector<Finding> scan_staging_exposure(const Config &, HttpClient &http,
                                           const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> paths = {
      "/staging/", "/test/", "/dev/", "/uat/", "/beta/",
      "/stage/", "/_staging/", "/pre-prod/"};
  for (const auto &path : paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 && resp.body.size() > 200) {
      findings.push_back({"Staging Exposure", "medium", base + path,
                          "Staging/test environment accessible", "", "", ""});
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
      {"Open Ports", scan_open_ports},
      {"DNS Rebinding", scan_dns_rebinding},
      {"Subdomain Permutation", scan_subdomain_permutation},
      {"Staging Exposure", scan_staging_exposure},
  };
}

} // namespace apex
