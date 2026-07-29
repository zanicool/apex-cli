/// @file subdomain_enum.cpp
/// @brief Subdomain Enumeration Engine — DNS brute-force + CT logs + takeover.
#include "subdomain_enum.hpp"

#include <algorithm>
#include <regex>
#include <set>
#include <sstream>

namespace apex {

std::vector<std::string> SubdomainEnum::get_prefixes() {
  return {
      "www",        "mail",       "ftp",        "dev",        "staging",
      "api",        "admin",      "test",       "beta",       "internal",
      "vpn",        "git",        "ci",         "jenkins",    "grafana",
      "kibana",     "elastic",    "prometheus", "status",     "monitor",
      "dashboard",  "portal",     "app",        "mobile",     "m",
      "shop",       "store",      "blog",       "news",       "support",
      "help",       "docs",       "wiki",       "cdn",        "static",
      "assets",     "media",      "img",        "images",     "video",
      "files",      "download",   "upload",     "backup",     "bak",
      "old",        "new",        "v2",         "v3",         "alpha",
      "demo",       "sandbox",    "uat",        "qa",         "stage",
      "preprod",    "pre",        "prod",       "production", "live",
      "web",        "www2",       "www3",       "ns1",        "ns2",
      "ns3",        "dns",        "dns1",       "dns2",       "mx",
      "mx1",        "mx2",       "smtp",       "pop",        "imap",
      "exchange",   "owa",        "autodiscover", "webmail",  "remote",
      "vpn2",       "gateway",    "proxy",      "cache",      "edge",
      "lb",         "load",       "node1",      "node2",      "node3",
      "db",         "database",   "mysql",      "postgres",   "mongo",
      "redis",      "memcached",  "rabbit",     "rabbitmq",   "kafka",
      "mq",         "queue",      "worker",     "scheduler",  "cron",
      "jobs",       "task",       "service",    "svc",        "micro",
      "auth",       "login",      "sso",        "oauth",      "id",
      "identity",   "iam",        "accounts",   "account",    "user",
      "users",      "profile",    "member",     "members",    "customer",
      "clients",    "partner",    "partners",   "vendor",     "suppliers",
      "hr",         "finance",    "billing",    "pay",        "payment",
      "payments",   "invoice",    "order",      "orders",     "cart",
      "checkout",   "crm",        "erp",        "sales",      "marketing",
      "analytics",  "tracking",   "events",     "log",        "logs",
      "logging",    "sentry",     "bugsnag",    "airbrake",   "newrelic",
      "datadog",    "splunk",     "graylog",    "nagios",     "zabbix",
      "icinga",     "consul",     "vault",      "terraform",  "ansible",
      "puppet",     "chef",       "docker",     "k8s",        "kubernetes",
      "rancher",    "swarm",      "registry",   "harbor",     "nexus",
      "artifactory","sonar",      "sonarqube",  "jira",       "confluence",
      "bitbucket",  "gitlab",     "github",     "circleci",   "travis",
      "drone",      "bamboo",     "teamcity",   "octopus",    "deploy",
      "release",    "build",      "compile",    "package",    "npm",
      "pip",        "gem",        "maven",      "gradle",     "cargo",
      "go",         "rust",       "python",     "java",       "php",
      "ruby",       "node",       "react",      "angular",    "vue",
      "next",       "nuxt",       "svelte",     "graphql",    "rest",
      "grpc",       "soap",       "ws",         "websocket",  "socket",
      "realtime",   "push",       "notify",     "notification","alerts",
      "slack",      "teams",      "chat",       "message",    "messages",
      "inbox",      "outbox",     "queue2",     "pubsub",     "stream",
      "feed",       "rss",        "atom",       "webhook",    "hook",
      "hooks",      "callback",   "redirect",   "link",       "links",
      "short",      "url",        "share",      "embed",      "widget",
      "sdk",        "lib",        "library",    "pkg",        "dist",
      "s3",         "storage",    "bucket",     "blob",       "object",
      "archive",    "vault2",     "secret",     "secrets",    "key",
      "keys",       "cert",       "certs",      "ssl",        "tls",
      "crypto",     "sign",       "verify",     "validate",   "check",
      "health",     "healthcheck","ping",       "heartbeat",  "alive",
  };
}

std::set<std::string>
SubdomainEnum::brute_force_dns(const std::string &domain, HttpClient &http) {
  std::set<std::string> found;
  auto prefixes = get_prefixes();

  for (const auto &prefix : prefixes) {
    std::string subdomain = prefix + "." + domain;
    // We use HTTP probe — if it resolves and returns anything, it exists
    std::string url = "https://" + subdomain;
    auto resp = http.get(url);

    if (resp.status_code > 0 && resp.error.empty()) {
      found.insert(subdomain);
    } else {
      // Try HTTP (non-TLS)
      url = "http://" + subdomain;
      resp = http.get(url);
      if (resp.status_code > 0 && resp.error.empty()) {
        found.insert(subdomain);
      }
    }
  }

  return found;
}

std::set<std::string>
SubdomainEnum::ct_log_lookup(const std::string &domain, HttpClient &http) {
  std::set<std::string> subdomains;

  // Use crt.sh API
  std::string url = "https://crt.sh/?q=%25." + domain + "&output=json";
  auto resp = http.get(url);

  if (resp.status_code != 200 || resp.body.empty())
    return subdomains;

  // Parse JSON for name_value fields
  std::regex name_re(R"("name_value"\s*:\s*"([^"]+))");
  auto begin =
      std::sregex_iterator(resp.body.begin(), resp.body.end(), name_re);
  for (auto it = begin; it != std::sregex_iterator(); ++it) {
    std::string name = (*it)[1].str();
    std::istringstream ss(name);
    std::string line;
    while (std::getline(ss, line, '\n')) {
      if (line.empty() || line[0] == '*')
        continue;
      // Remove leading/trailing whitespace
      while (!line.empty() && (line.front() == ' ' || line.front() == '\t'))
        line.erase(line.begin());
      while (!line.empty() && (line.back() == ' ' || line.back() == '\t' ||
                               line.back() == '\r'))
        line.pop_back();
      if (line.find(domain) != std::string::npos) {
        subdomains.insert(line);
      }
    }
  }

  return subdomains;
}

bool SubdomainEnum::resolves(const std::string &hostname, HttpClient &http) {
  std::string url = "https://" + hostname;
  auto resp = http.get(url);
  if (resp.status_code > 0 && resp.error.empty())
    return true;
  url = "http://" + hostname;
  resp = http.get(url);
  return resp.status_code > 0 && resp.error.empty();
}

std::vector<Finding>
SubdomainEnum::check_takeover(const std::string &subdomain, HttpClient &http) {
  std::vector<Finding> findings;

  std::string url = "https://" + subdomain;
  auto resp = http.get(url);
  if (resp.status_code == 0 || resp.error.find("resolve") != std::string::npos) {
    // Try HTTP
    url = "http://" + subdomain;
    resp = http.get(url);
  }

  if (resp.status_code == 0)
    return findings;

  // Check for subdomain takeover fingerprints
  std::vector<std::pair<std::string, std::string>> takeover_sigs = {
      {"There isn't a GitHub Pages site here", "GitHub Pages"},
      {"NoSuchBucket", "AWS S3"},
      {"No such app", "Heroku"},
      {"Sorry, this shop is currently unavailable", "Shopify"},
      {"The request could not be satisfied", "AWS CloudFront"},
      {"Fastly error: unknown domain", "Fastly"},
      {"There's nothing here, yet.", "Tumblr"},
      {"Do you want to register", "WordPress"},
      {"The feed has not been found", "Feedpress"},
      {"Sorry, We Couldn't Find That Page", "Help Scout"},
      {"No settings were found for this company", "Help Juice"},
      {"is not a registered InCloud YouTrack", "JetBrains"},
      {"Unrecognized domain", "Mashery"},
      {"Project doesnt exist", "Readme.io"},
      {"This UserVoice subdomain is currently available", "UserVoice"},
      {"account has been suspended", "Surge.sh"},
      {"page not found", "Bitbucket"},
      {"Repository not found", "Bitbucket"},
      {"This page is reserved for artistic", "Strikingly"},
      {"<title>Hosted by Vercel</title>", "Vercel"},
  };

  std::string body_lower = resp.body;
  std::transform(body_lower.begin(), body_lower.end(), body_lower.begin(),
                 ::tolower);

  for (const auto &[sig, service] : takeover_sigs) {
    std::string sig_lower = sig;
    std::transform(sig_lower.begin(), sig_lower.end(), sig_lower.begin(),
                   ::tolower);
    if (body_lower.find(sig_lower) != std::string::npos) {
      Finding f;
      f.type = "subdomain-takeover";
      f.severity = "critical";
      f.url = url;
      f.detail = "Subdomain takeover possible via " + service + " on " +
                 subdomain;
      f.payload = subdomain;
      f.evidence = "Takeover signature found: " + sig;
      f.confidence = 85;
      f.cwe_id = "CWE-284";
      f.owasp_category = "A05:2021 Security Misconfiguration";
      f.cvss_score = 9.1;
      findings.push_back(f);
      break;
    }
  }

  // CNAME to non-existent domain (dangling DNS)
  if (resp.status_code == 0 &&
      (resp.error.find("resolve") != std::string::npos ||
       resp.error.find("Could not") != std::string::npos)) {
    Finding f;
    f.type = "subdomain-dangling-dns";
    f.severity = "high";
    f.url = "https://" + subdomain;
    f.detail = "Dangling DNS record — subdomain does not resolve (potential "
               "takeover)";
    f.payload = subdomain;
    f.evidence = "DNS resolution failed: " + resp.error;
    f.confidence = 60;
    f.cwe_id = "CWE-284";
    f.owasp_category = "A05:2021 Security Misconfiguration";
    f.cvss_score = 7.5;
    findings.push_back(f);
  }

  return findings;
}

std::vector<Finding>
SubdomainEnum::enumerate(const std::string &domain, HttpClient &http) {
  std::vector<Finding> findings;

  // Phase 1: Certificate Transparency lookup
  auto ct_subs = ct_log_lookup(domain, http);

  // Phase 2: DNS brute-force
  auto brute_subs = brute_force_dns(domain, http);

  // Merge all discovered subdomains
  std::set<std::string> all_subs;
  all_subs.insert(ct_subs.begin(), ct_subs.end());
  all_subs.insert(brute_subs.begin(), brute_subs.end());

  // Report discovered subdomains
  for (const auto &sub : all_subs) {
    // Check if it resolves and test for takeover
    auto takeover_findings = check_takeover(sub, http);
    findings.insert(findings.end(), takeover_findings.begin(),
                    takeover_findings.end());

    // Report as info finding
    Finding f;
    f.type = "subdomain-discovered";
    f.severity = "info";
    f.url = "https://" + sub;
    f.detail = "Active subdomain discovered: " + sub;
    f.payload = sub;
    std::string source = "brute-force";
    if (ct_subs.count(sub))
      source = "CT-log";
    if (brute_subs.count(sub) && ct_subs.count(sub))
      source = "CT-log+brute-force";
    f.evidence = "Source: " + source;
    f.confidence = 95;
    f.cwe_id = "";
    f.owasp_category = "A05:2021 Security Misconfiguration";
    f.cvss_score = 0.0;
    findings.push_back(f);
  }

  // Summary finding
  if (!all_subs.empty()) {
    Finding f;
    f.type = "subdomain-enumeration-summary";
    f.severity = "info";
    f.url = "https://" + domain;
    f.detail = "Found " + std::to_string(all_subs.size()) +
               " subdomains for " + domain;
    f.evidence = "CT: " + std::to_string(ct_subs.size()) +
                 ", Brute-force: " + std::to_string(brute_subs.size());
    f.confidence = 100;
    findings.push_back(f);
  }

  return findings;
}

} // namespace apex
