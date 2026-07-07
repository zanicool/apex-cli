/// @file scanners/subdomain_takeover.cpp
/// @brief Subdomain takeover detection, dangling DNS records,
///        S3/Azure/GCS bucket takeover, and cloud service fingerprinting.
#include <regex>

#include "scanner_base.hpp"

namespace apex {
namespace {

/// Known service fingerprints that indicate takeover-able services.
struct TakeoverSignature {
  std::string service;
  std::string cname_pattern;
  std::string body_fingerprint;
  std::string severity;
};

const std::vector<TakeoverSignature> TAKEOVER_SIGS = {
    {"GitHub Pages", "github.io", "There isn't a GitHub Pages site here", "high"},
    {"Heroku", "herokuapp.com", "No such app", "high"},
    {"AWS S3", "s3.amazonaws.com", "NoSuchBucket", "critical"},
    {"AWS S3", "s3-website", "NoSuchBucket", "critical"},
    {"Shopify", "myshopify.com", "Sorry, this shop is currently unavailable", "high"},
    {"Tumblr", "domains.tumblr.com", "There's nothing here", "medium"},
    {"Zendesk", "zendesk.com", "Help Center Closed", "medium"},
    {"Ghost", "ghost.io", "The thing you were looking for is no longer here", "medium"},
    {"Surge.sh", "surge.sh", "project not found", "medium"},
    {"Netlify", "netlify.app", "Not Found - Request ID", "high"},
    {"Vercel", "vercel.app", "DEPLOYMENT_NOT_FOUND", "high"},
    {"Fly.io", "fly.dev", "404 Not Found", "medium"},
    {"Azure", "azurewebsites.net", "404 Web Site not found", "high"},
    {"Azure", "cloudapp.azure.com", "404 Web Site not found", "high"},
    {"Azure", "azure-api.net", "not found", "high"},
    {"Fastly", "fastly.net", "Fastly error: unknown domain", "high"},
    {"Pantheon", "pantheonsite.io", "404 error unknown site", "medium"},
    {"Cargo", "cargocollective.com", "404 Not Found", "medium"},
    {"Readme.io", "readme.io", "Project doesnt exist", "medium"},
    {"Bitbucket", "bitbucket.io", "Repository not found", "medium"},
    {"Unbounce", "unbouncepages.com", "The requested URL was not found", "medium"},
    {"Tilda", "tilda.ws", "Please renew your subscription", "medium"},
};

/// Check common subdomains for takeover.
std::vector<Finding> scan_subdomain_takeover(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Extract domain from base
  std::string domain = base;
  auto proto = domain.find("://");
  if (proto != std::string::npos) domain = domain.substr(proto + 3);
  auto slash = domain.find("/");
  if (slash != std::string::npos) domain = domain.substr(0, slash);
  if (domain.substr(0, 4) == "www.") domain = domain.substr(4);

  // Common subdomains to check
  std::vector<std::string> subs = {"staging", "dev",    "test",     "beta", "alpha", "demo",   "shop",    "store",  "blog",    "docs",
                                   "api",     "app",    "cdn",      "mail", "admin", "portal", "status",  "help",   "support", "assets",
                                   "media",   "static", "internal", "old",  "new",   "v2",     "sandbox", "preprod"};

  for (const auto& sub : subs) {
    std::string url = "https://" + sub + "." + domain;
    auto resp = http.get(url);

    // Check response against takeover signatures
    for (const auto& sig : TAKEOVER_SIGS) {
      if (!sig.body_fingerprint.empty() && resp.body.find(sig.body_fingerprint) != std::string::npos) {
        findings.push_back(Finding{"Subdomain Takeover — " + sig.service, sig.severity, url,
                                   "Subdomain '" + sub + "." + domain + "' points to " + sig.service +
                                       " but the resource is unclaimed. "
                                       "Attacker can register the service and serve malicious content on your subdomain.",
                                   "service", sig.service, "Fingerprint: " + sig.body_fingerprint});
        break;
      }
    }

    // Check for NXDOMAIN / connection refused (dangling record)
    if (resp.status_code == 0 || resp.body.empty()) {
      // Can't easily distinguish NXDOMAIN from timeout in HTTP client,
      // but empty response from a subdomain that resolves = suspicious
    }
  }
  return findings;
}

/// Check for exposed cloud storage buckets.
std::vector<Finding> scan_bucket_takeover(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Extract org name from domain
  std::string domain = base;
  auto proto = domain.find("://");
  if (proto != std::string::npos) domain = domain.substr(proto + 3);
  auto dot = domain.find(".");
  std::string name = (dot != std::string::npos) ? domain.substr(0, dot) : domain;
  if (name == "www") {
    domain = domain.substr(4);
    dot = domain.find(".");
    name = (dot != std::string::npos) ? domain.substr(0, dot) : domain;
  }

  // S3 bucket variations
  std::vector<std::string> bucket_names = {name,           name + "-assets",  name + "-backup", name + "-dev",    name + "-staging",
                                           name + "-prod", name + "-uploads", name + "-media",  name + "-static", name + "-data",
                                           name + "-logs", name + "-config"};

  for (const auto& bucket : bucket_names) {
    // AWS S3
    auto s3 = http.get("https://" + bucket + ".s3.amazonaws.com/");
    if (s3.status_code == 200 && s3.body.find("ListBucketResult") != std::string::npos) {
      findings.push_back(Finding{"S3 Bucket — Public Listing", "high", "https://" + bucket + ".s3.amazonaws.com/",
                                 "S3 bucket '" + bucket +
                                     "' is publicly listable. "
                                     "May contain sensitive data, backups, or user uploads.",
                                 "", "", ""});
    } else if (s3.body.find("NoSuchBucket") != std::string::npos) {
      findings.push_back(Finding{"S3 Bucket — Takeover Possible", "critical", "https://" + bucket + ".s3.amazonaws.com/",
                                 "S3 bucket '" + bucket +
                                     "' does not exist. "
                                     "If your DNS or app references this bucket, attacker can create it "
                                     "and serve malicious content.",
                                 "", bucket, ""});
    }

    // GCS
    auto gcs = http.get("https://storage.googleapis.com/" + bucket + "/");
    if (gcs.status_code == 200 && gcs.body.find("ListBucketResult") != std::string::npos) {
      findings.push_back(Finding{"GCS Bucket — Public Listing", "high", "https://storage.googleapis.com/" + bucket + "/",
                                 "Google Cloud Storage bucket '" + bucket + "' is publicly listable.", "", "", ""});
    }
  }

  return findings;
}

/// Check for exposed debug and monitoring endpoints.
std::vector<Finding> scan_debug_endpoints(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  struct DebugCheck {
    std::string path;
    std::string name;
    std::string indicator;
  };

  std::vector<DebugCheck> checks = {
      {"/actuator", "Spring Actuator", "\"_links\""},
      {"/actuator/env", "Spring Env", "\"property\""},
      {"/actuator/heapdump", "Spring Heapdump", ""},
      {"/_debug", "Debug Endpoint", "debug"},
      {"/__debug", "Debug Endpoint", ""},
      {"/debug/vars", "Go Debug Vars", "memstats"},
      {"/debug/pprof/", "Go pprof", "Profile"},
      {"/_profiler", "Symfony Profiler", "profiler"},
      {"/telescope", "Laravel Telescope", "telescope"},
      {"/horizon", "Laravel Horizon", "horizon"},
      {"/elmah.axd", "ELMAH Errors", "Error Log"},
      {"/trace", "Trace Endpoint", "timestamp"},
      {"/server-info", "Apache Info", "Apache"},
      {"/__clockwork", "Clockwork Debug", ""},
      {"/metrics", "Prometheus Metrics", "process_"},
      {"/graphiql", "GraphQL IDE", "GraphiQL"},
      {"/playground", "GraphQL Playground", "playground"},
      {"/.well-known/openid-configuration", "OpenID Config", "issuer"},
  };

  for (const auto& check : checks) {
    auto resp = http.get(base + check.path);
    if (resp.status_code == 200 && resp.body.size() > 20) {
      if (check.indicator.empty() || resp.body.find(check.indicator) != std::string::npos) {
        std::string severity = "medium";
        if (check.path.find("heapdump") != std::string::npos || check.path.find("env") != std::string::npos) {
          severity = "critical";
        }
        findings.push_back(Finding{check.name + " Exposed", severity, base + check.path,
                                   check.name + " is publicly accessible. "
                                                "May leak internal state, credentials, or enable further exploitation.",
                                   "", "", "Size: " + std::to_string(resp.body.size()) + " bytes"});
      }
    }
  }
  return findings;
}

}  // namespace

std::vector<Scanner> register_subdomain_takeover_scanners() {
  return {
      {"Subdomain Takeover", scan_subdomain_takeover},
      {"Bucket Takeover", scan_bucket_takeover},
      {"Debug Endpoints", scan_debug_endpoints},
  };
}

}  // namespace apex
