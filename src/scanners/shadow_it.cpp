/// @file scanners/shadow_it.cpp
/// @brief Shadow IT discovery: detects unauthorized SaaS, AI tools, OAuth apps,
///        exposed internal services, forgotten subdomains, rogue cloud resources,
///        and data leakage indicators via DNS, HTTP, and public source analysis.
#include <set>

#include "scanner_base.hpp"

namespace apex {
namespace {

std::string get_domain(const Config& cfg) {
  std::string d = cfg.target;
  if (d.find("://") != std::string::npos) d = d.substr(d.find("://") + 3);
  if (d.find('/') != std::string::npos) d = d.substr(0, d.find('/'));
  if (d.find(':') != std::string::npos) d = d.substr(0, d.find(':'));
  return d;
}

/// Discover shadow SaaS/AI services via DNS CNAME records and subdomains.
std::vector<Finding> scan_shadow_saas(const Config& cfg, HttpClient& http, const CrawlResult&) {
  std::vector<Finding> findings;
  std::string domain = get_domain(cfg);
  std::string org = domain.substr(0, domain.find('.'));

  // Common shadow IT subdomains that indicate unmanaged services.
  struct ShadowService {
    const char* subdomain;
    const char* service;
    const char* risk;
  };
  const ShadowService shadow_subs[] = {
      // AI / Productivity
      {"chat", "Internal ChatGPT/AI proxy", "AI data leakage"},
      {"ai", "AI service", "AI data leakage"},
      {"gpt", "GPT proxy", "AI data leakage"},
      {"copilot", "Copilot instance", "AI data leakage"},
      // Collaboration
      {"notion", "Notion workspace", "data in unmanaged SaaS"},
      {"slack", "Slack instance", "shadow messaging"},
      {"miro", "Miro board", "data exposure"},
      {"wiki", "Wiki (possibly unmanaged)", "knowledge leak"},
      {"docs", "Documentation", "possible shadow docs"},
      // DevOps
      {"jenkins", "Jenkins CI", "exposed CI/CD"},
      {"gitlab", "GitLab instance", "shadow code hosting"},
      {"drone", "Drone CI", "exposed CI/CD"},
      {"argo", "ArgoCD", "exposed GitOps"},
      {"harbor", "Harbor registry", "exposed container images"},
      {"sonar", "SonarQube", "code quality data"},
      {"nexus", "Nexus repository", "artifact exposure"},
      // Monitoring / Observability
      {"grafana", "Grafana dashboard", "metrics exposure"},
      {"kibana", "Kibana/ELK", "log data exposure"},
      {"prometheus", "Prometheus", "metrics exposure"},
      {"sentry", "Sentry error tracking", "stack trace leaks"},
      {"datadog", "Datadog proxy", "observability data"},
      // Automation
      {"n8n", "n8n automation", "workflow data + RCE risk"},
      {"zapier", "Zapier webhook", "automation data flow"},
      {"webhook", "Webhook endpoint", "unmanaged integrations"},
      {"hooks", "Webhook endpoint", "unmanaged integrations"},
      // Storage / Data
      {"minio", "MinIO storage", "exposed object storage"},
      {"files", "File server", "data exposure"},
      {"backup", "Backup service", "sensitive data"},
      {"nas", "NAS device", "data exposure"},
      {"share", "File sharing", "data exposure"},
      // Internal tools
      {"vpn", "VPN endpoint", "network access"},
      {"remote", "Remote access", "network access"},
      {"rdp", "RDP gateway", "network access"},
      {"bastion", "Bastion host", "network access"},
      {"jump", "Jump server", "network access"},
      // Forgotten / legacy
      {"old", "Legacy service", "unpatched"},
      {"legacy", "Legacy service", "unpatched"},
      {"test", "Test environment", "possible data leak"},
      {"staging", "Staging environment", "possible data leak"},
      {"dev", "Dev environment", "possible data leak"},
      {"demo", "Demo environment", "possible data leak"},
      {"beta", "Beta service", "unmanaged"},
      {"temp", "Temporary service", "forgotten resource"},
  };

  for (const auto& s : shadow_subs) {
    std::string url = "https://" + std::string(s.subdomain) + "." + domain;
    auto resp = http.get(url);
    if (resp.status_code >= 200 && resp.status_code < 500 && resp.status_code != 404 && resp.body.size() > 50) {
      findings.push_back(
          {"Shadow IT: " + std::string(s.service), "medium", url, std::string(s.service) + " detected — risk: " + s.risk, "", "", ""});
    }
  }
  return findings;
}

/// Detect OAuth/SSO sprawl and third-party integrations.
std::vector<Finding> scan_oauth_sprawl(const Config& cfg, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);
  std::string domain = get_domain(cfg);

  // Check for OAuth endpoints that reveal connected apps.
  const std::vector<std::string> oauth_paths = {
      "/oauth/applications", "/.well-known/openid-configuration", "/api/v1/oauth/apps",
      "/admin/oauth",        "/oauth/authorized_applications",    "/settings/applications",
      "/api/connected-apps",
  };
  for (const auto& path : oauth_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 && resp.body.size() > 100 &&
        (resp.body.find("client_id") != std::string::npos || resp.body.find("redirect_uri") != std::string::npos ||
         resp.body.find("scope") != std::string::npos)) {
      findings.push_back({"OAuth App List Exposed", "high", base + path,
                          "OAuth application registry accessible — "
                          "reveals all connected third-party apps",
                          "", "", ""});
    }
  }

  // Check for overly permissive OAuth scopes in page source.
  auto home = http.get(base + "/");
  const std::vector<std::string> risky_scopes = {"https://www.googleapis.com/auth/drive",
                                                 "https://www.googleapis.com/auth/gmail",
                                                 "repo",
                                                 "admin:org",
                                                 "write:packages",
                                                 "Files.ReadWrite.All",
                                                 "Mail.ReadWrite",
                                                 "Sites.FullControl.All"};
  for (const auto& scope : risky_scopes) {
    if (home.body.find(scope) != std::string::npos) {
      findings.push_back({"Risky OAuth Scope", "high", base, "Overly permissive OAuth scope in source: " + scope, "", "", ""});
    }
  }

  // Check Microsoft tenant for app registrations (public endpoint).
  auto tenant = http.get("https://login.microsoftonline.com/" + domain + "/v2.0/.well-known/openid-configuration");
  if (tenant.status_code == 200 && tenant.body.find("authorization_endpoint") != std::string::npos) {
    findings.push_back({"M365 Tenant (OAuth target)", "info", "https://login.microsoftonline.com/" + domain,
                        "M365 tenant confirmed — check for consent phishing "
                        "and unmanaged OAuth app grants",
                        "", "", ""});
  }

  return findings;
}

/// Detect exposed internal dashboards and monitoring tools.
std::vector<Finding> scan_exposed_dashboards(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  struct Dashboard {
    const char* path;
    const char* name;
    const char* indicator;
  };
  const Dashboard dashboards[] = {
      {"/grafana/", "Grafana", "grafana"},
      {"/-/dashboard", "Grafana", "grafana"},
      {"/kibana/", "Kibana", "kibana"},
      {"/app/kibana", "Kibana", "kibana"},
      {"/_plugin/kibana/", "Kibana (ES plugin)", "kibana"},
      {"/prometheus/", "Prometheus", "prometheus"},
      {"/prometheus/graph", "Prometheus", "query_range"},
      {"/jaeger/", "Jaeger tracing", "jaeger"},
      {"/zipkin/", "Zipkin tracing", "zipkin"},
      {"/flower/", "Celery Flower", "flower"},
      {"/rabbitmq/", "RabbitMQ Management", "rabbitmq"},
      {"/pgadmin/", "pgAdmin", "pgAdmin"},
      {"/phppgadmin/", "phpPgAdmin", "phpPgAdmin"},
      {"/mailhog/", "MailHog", "mailhog"},
      {"/portainer/", "Portainer", "portainer"},
      {"/traefik/dashboard/", "Traefik", "traefik"},
      {"/consul/", "Consul UI", "consul"},
      {"/vault/ui/", "HashiCorp Vault", "vault"},
      {"/argocd/", "ArgoCD", "argo"},
      {"/weave/", "Weave Scope", "weave"},
      {"/rancher/", "Rancher", "rancher"},
      {"/longhorn/", "Longhorn", "longhorn"},
      {"/superset/", "Apache Superset", "superset"},
      {"/metabase/", "Metabase", "metabase"},
      {"/redash/", "Redash", "redash"},
  };

  for (const auto& d : dashboards) {
    auto resp = http.get(base + d.path);
    if (resp.status_code == 200 && resp.body.size() > 200 && resp.body.find(d.indicator) != std::string::npos) {
      findings.push_back({"Exposed Dashboard: " + std::string(d.name), "high", base + d.path,
                          std::string(d.name) + " accessible without auth — "
                                                "leaks internal metrics/data",
                          "", "", ""});
    }
  }
  return findings;
}

/// Detect AI tool usage indicators and data leakage vectors.
std::vector<Finding> scan_ai_leakage(const Config& cfg, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);
  std::string domain = get_domain(cfg);

  // Check for AI proxy/gateway endpoints.
  const std::vector<std::pair<std::string, std::string>> ai_paths = {
      {"/api/chat", "Internal chat API (possible AI proxy)"},     {"/api/v1/chat/completions", "OpenAI-compatible API endpoint"},
      {"/v1/chat/completions", "OpenAI-compatible API endpoint"}, {"/api/generate", "Ollama/local LLM endpoint"},
      {"/api/embeddings", "Embedding API (data ingestion)"},      {"/litellm/", "LiteLLM proxy"},
  };
  for (const auto& [path, desc] : ai_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 || resp.status_code == 401 || resp.status_code == 405) {
      findings.push_back({"AI Endpoint Exposed", "high", base + path, desc + " — possible corporate data flowing to AI", "", "", ""});
    }
  }

  // Check for MCP (Model Context Protocol) servers.
  const std::vector<std::string> mcp_paths = {"/mcp", "/api/mcp", "/.well-known/mcp.json"};
  for (const auto& path : mcp_paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 && resp.body.size() > 20) {
      findings.push_back({"MCP Server Exposed", "high", base + path,
                          "Model Context Protocol server accessible — "
                          "AI agents may access internal systems",
                          "", "", ""});
    }
  }

  // Check DNS for AI-related subdomains.
  const std::vector<std::string> ai_subs = {"openai", "claude", "llm", "chatbot", "assistant", "ollama"};
  for (const auto& sub : ai_subs) {
    auto resp = http.get("https://" + sub + "." + domain + "/");
    if (resp.status_code >= 200 && resp.status_code < 500 && resp.status_code != 404 && resp.body.size() > 50) {
      findings.push_back({"Shadow AI Service", "medium", "https://" + sub + "." + domain,
                          "AI-related subdomain active — possible unmanaged AI gateway", "", "", ""});
    }
  }

  return findings;
}

/// Detect forgotten/orphaned resources and rogue cloud infrastructure.
std::vector<Finding> scan_orphaned_resources(const Config& cfg, HttpClient& http, const CrawlResult&) {
  std::vector<Finding> findings;
  std::string domain = get_domain(cfg);
  std::string org = domain.substr(0, domain.find('.'));

  // Check for rogue cloud resources via common naming patterns.
  struct CloudPattern {
    const char* url_template;  // %s = org name
    const char* name;
    const char* indicator;
  };
  const CloudPattern patterns[] = {
      {"https://%s-dev.s3.amazonaws.com/", "Rogue S3 (dev)", "ListBucket"},
      {"https://%s-test.s3.amazonaws.com/", "Rogue S3 (test)", "ListBucket"},
      {"https://%s-temp.s3.amazonaws.com/", "Rogue S3 (temp)", "ListBucket"},
      {"https://%s-personal.s3.amazonaws.com/", "Rogue S3 (personal)", "ListBucket"},
      {"https://%s-old.s3.amazonaws.com/", "Rogue S3 (old)", "ListBucket"},
      {"https://%s.blob.core.windows.net/test?restype=container&comp=list", "Rogue Azure Blob (test)", "<Blob>"},
      {"https://%s.blob.core.windows.net/temp?restype=container&comp=list", "Rogue Azure Blob (temp)", "<Blob>"},
  };

  for (const auto& p : patterns) {
    char url[512];
    snprintf(url, sizeof(url), p.url_template, org.c_str());
    auto resp = http.get(url);
    if (resp.status_code == 200 && resp.body.find(p.indicator) != std::string::npos) {
      findings.push_back(
          {"Orphaned Cloud Resource", "high", url, std::string(p.name) + " — publicly listable, likely unmanaged", "", "", ""});
    }
  }

  // Check for forgotten Heroku/Vercel/Netlify deployments.
  // Skip generic org names that always produce FPs
  static const std::vector<std::string> generic_orgs = {
    "example", "test", "app", "www", "web", "api", "dev", "admin", "demo", "staging", "beta"
  };
  bool is_generic = std::find(generic_orgs.begin(), generic_orgs.end(), org) != generic_orgs.end() || org.length() <= 4;

  if (!is_generic) {
    const std::vector<std::pair<std::string, std::string>> deploy_patterns = {
        {"https://" + org + ".herokuapp.com", "Heroku"},     {"https://" + org + ".vercel.app", "Vercel"},
        {"https://" + org + ".netlify.app", "Netlify"},      {"https://" + org + ".azurewebsites.net", "Azure App Service"},
        {"https://" + org + ".firebaseapp.com", "Firebase"}, {"https://" + org + ".web.app", "Firebase"},
    };
    for (const auto& [url, platform] : deploy_patterns) {
      auto resp = http.get(url);
      if (resp.status_code == 200 && resp.body.size() > 200) {
        findings.push_back(
            {"Shadow Deployment: " + platform, "medium", url, platform + " deployment found — possibly unmanaged/forgotten", "", "", ""});
      }
    }
  }

  return findings;
}

}  // namespace

std::vector<Scanner> register_shadow_it_scanners() {
  return {
      {"Shadow SaaS/Subdomains", scan_shadow_saas},    {"OAuth Sprawl", scan_oauth_sprawl},
      {"Exposed Dashboards", scan_exposed_dashboards}, {"AI Leakage Detection", scan_ai_leakage},
      {"Orphaned Resources", scan_orphaned_resources},
  };
}

}  // namespace apex
