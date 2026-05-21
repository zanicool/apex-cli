/// @file scanners/cloud_misconfig.cpp
/// @brief Cloud misconfiguration: Azure Blob, GCP buckets, expanded S3,
///        cloud IAM metadata, Kubernetes dashboard, exposed admin panels.
#include "scanner_base.hpp"
#include <set>

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

/// Scanner implementation.
/// @brief Scan for azure_blob vulnerabilities.
std::vector<Finding> scan_azure_blob(const Config &cfg, HttpClient &http,
                                     const CrawlResult &crawl) {
  // Accumulate findings for this scanner.
  // Accumulate findings for this scanner.
  // Accumulate findings for this scanner.
  std::vector<Finding> findings;
  // Extract domain from target.
  // Extract domain from target.
  // Extract domain from target.
  std::string domain = cfg.target;
  // Strip protocol.
  if (domain.find("://") != std::string::npos)
    domain = domain.substr(domain.find("://") + 3);
  if (domain.find('/') != std::string::npos)
    domain = domain.substr(0, domain.find('/'));
  // Extract org name.
  // Extract organization name from domain.
  // Extract organization name from domain.
  // Extract organization name from domain.
  std::string org = domain.substr(0, domain.find('.'));

  // Azure Blob storage patterns.
  const std::vector<std::string> containers = {
      "data", "backup", "backups", "uploads", "static", "assets",
      "logs", "media", "public", "private", "dev", "staging", "prod"};

  // Iterate over targets.
  for (const auto &container : containers) {
    std::string url = "https://" + org + ".blob.core.windows.net/" + container + "?restype=container&comp=list";
    auto resp = http.get(url);
    if (resp.status_code == 200 && resp.body.find("<Blob>") != std::string::npos) {
      findings.push_back({"Azure Blob Public", "high", url,
                          "Azure Blob container '" + container + "' is publicly listable",
                          "", "", ""});
    }
  }
  // Return collected findings.
  // Return collected findings.
  // Return collected findings.
  return findings;
}

/// Scanner implementation.
/// @brief Scan for gcp_bucket vulnerabilities.
std::vector<Finding> scan_gcp_bucket(const Config &cfg, HttpClient &http,
                                     const CrawlResult &) {
  std::vector<Finding> findings;
  std::string domain = cfg.target;
  if (domain.find("://") != std::string::npos)
    domain = domain.substr(domain.find("://") + 3);
  if (domain.find('/') != std::string::npos)
    domain = domain.substr(0, domain.find('/'));
  std::string org = domain.substr(0, domain.find('.'));

  const std::vector<std::string> buckets = {
      org, org + "-backup", org + "-data", org + "-uploads",
      org + "-assets", org + "-static", org + "-dev", org + "-prod",
      org + "-staging", org + "-logs", org + "-ml", org + "-models"};

  // Iterate over targets.
  for (const auto &bucket : buckets) {
    std::string url = "https://storage.googleapis.com/" + bucket;
    auto resp = http.get(url);
    if (resp.status_code == 200 &&
        (resp.body.find("<Contents>") != std::string::npos ||
         resp.body.find("<ListBucketResult") != std::string::npos)) {
      findings.push_back({"GCP Bucket Public", "high", url,
                          "GCP bucket '" + bucket + "' is publicly listable",
                          "", "", ""});
    }
  }
  return findings;
}

/// Scanner implementation.
/// @brief Scan for s3_expanded vulnerabilities.
std::vector<Finding> scan_s3_expanded(const Config &cfg, HttpClient &http,
                                      const CrawlResult &crawl) {
  std::vector<Finding> findings;
  std::string domain = cfg.target;
  if (domain.find("://") != std::string::npos)
    domain = domain.substr(domain.find("://") + 3);
  if (domain.find('/') != std::string::npos)
    domain = domain.substr(0, domain.find('/'));
  std::string org = domain.substr(0, domain.find('.'));

  // Also check for S3 references in crawled pages.
  std::regex s3_re(R"((https?://[a-z0-9\-]+\.s3[.\-][a-z0-9\-]+\.amazonaws\.com|https?://s3[.\-][a-z0-9\-]+\.amazonaws\.com/[a-z0-9\-]+))");
  std::set<std::string> found_buckets;

  // Iterate over targets.
  // Process each crawled URL.
  // Process each crawled URL.
  // Process each crawled URL.
  for (const auto &url : crawl.urls) {
    auto resp = http.get(url);
    auto begin = std::sregex_iterator(resp.body.begin(), resp.body.end(), s3_re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it)
      found_buckets.insert((*it)[0].str());
  }

  // Test discovered + guessed buckets.
  const std::vector<std::string> guesses = {
      org + "-internal", org + "-secrets", org + "-config",
      org + "-terraform", org + "-ci", org + "-artifacts"};

  // Iterate over targets.
  for (const auto &b : guesses) {
    std::string url = "https://" + b + ".s3.amazonaws.com/";
    auto resp = http.get(url);
    if (resp.status_code == 200 && resp.body.find("<Contents>") != std::string::npos)
      found_buckets.insert(url);
  }

  // Iterate over targets.
  for (const auto &bucket : found_buckets) {
    auto resp = http.get(bucket);
    if (resp.status_code == 200 && resp.body.find("<Contents>") != std::string::npos) {
      findings.push_back({"S3 Bucket Listable", "high", bucket,
                          "S3 bucket publicly listable — check for sensitive data",
                          "", "", ""});
    }
  }
  return findings;
}

/// Scanner implementation.
/// @brief Scan for k8s_dashboard vulnerabilities.
std::vector<Finding> scan_k8s_dashboard(const Config &cfg, HttpClient &http,
                                        const CrawlResult &) {
  std::vector<Finding> findings;
  // Determine base URL for requests.
  // Determine base URL for requests.
  // Determine base URL for requests.
  std::string base = cfg.target.find("://") != std::string::npos
                         ? base_url_from(cfg.target) : "https://" + cfg.target;

  // Common K8s/admin panel paths.
  const std::vector<std::pair<std::string, std::string>> paths = {
      {"/dashboard/", "Kubernetes Dashboard"},
      {"/api/v1/namespaces", "Kubernetes API"},
      {"/_cat/indices", "Elasticsearch"},
      {"/_cluster/health", "Elasticsearch"},
      {"/solr/admin/", "Apache Solr"},
      {"/jenkins/", "Jenkins"},
      {"/actuator/env", "Spring Actuator"},
      {"/actuator/health", "Spring Actuator"},
      {"/server-status", "Apache Status"},
      {"/nginx_status", "Nginx Status"},
  };

  // Iterate over targets.
  for (const auto &[path, name] : paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 && resp.body.size() > 50 &&
        resp.body.find("unauthorized") == std::string::npos &&
        resp.body.find("403") == std::string::npos) {
      findings.push_back({"Exposed " + name, "high", base + path,
                          name + " accessible without authentication",
                          "", "", ""});
    }
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_cloud_misconfig_scanners() {
  return {
      {"Azure Blob Enum", scan_azure_blob},
      {"GCP Bucket Enum", scan_gcp_bucket},
      {"S3 Expanded", scan_s3_expanded},
      {"K8s/Admin Panels", scan_k8s_dashboard},
  };
}

} // namespace apex
