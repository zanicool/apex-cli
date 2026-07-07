/// @file scanners/cloud_attacks.cpp
/// @brief Cloud misconfiguration detection: finds exposed cloud services,
///        leaked credentials, and insecure configurations that indicate
///        exploitable weaknesses in cloud infrastructure.
#include <regex>

#include "scanner_base.hpp"

namespace apex {
namespace {

/// Docker Registry API exposed without auth.
std::vector<Finding> scan_docker_registry(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  auto resp = http.get(base + "/v2/_catalog");
  if (resp.status_code == 200 && resp.body.find("repositories") != std::string::npos && resp.body.find("[") != std::string::npos) {
    findings.push_back(Finding{"Docker Registry — Public Access", "critical", base + "/v2/_catalog",
                               "Docker registry API accessible without authentication. "
                               "Attacker can pull all container images (may contain secrets, source code).",
                               "", "/v2/_catalog", "Response contains repository listing"});
  }
  return findings;
}

/// Kubernetes API/dashboard exposed.
std::vector<Finding> scan_k8s_exposed(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // K8s dashboard
  auto dash = http.get(base + "/api/v1/namespaces");
  if (dash.status_code == 200 && dash.body.find("\"kind\":\"NamespaceList\"") != std::string::npos) {
    findings.push_back(Finding{"Kubernetes API — Unauthenticated", "critical", base + "/api/v1/namespaces",
                               "Kubernetes API server accessible without authentication. "
                               "Full cluster compromise possible (read secrets, deploy pods).",
                               "", "", "NamespaceList returned"});
  }

  // K8s dashboard UI
  auto ui = http.get(base + "/dashboard/");
  if (ui.status_code == 200 && ui.body.find("kubernetes-dashboard") != std::string::npos) {
    findings.push_back(Finding{"Kubernetes Dashboard — Exposed", "critical", base + "/dashboard/",
                               "Kubernetes Dashboard UI publicly accessible.", "", "", ""});
  }

  return findings;
}

/// Terraform state file exposed (contains all infra secrets).
std::vector<Finding> scan_terraform_state(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  std::vector<std::string> paths = {"/terraform.tfstate", "/.terraform/terraform.tfstate", "/tfstate", "/state.tf", "/main.tfstate"};

  for (const auto& path : paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 && resp.body.find("\"terraform_version\"") != std::string::npos &&
        resp.body.find("\"resources\"") != std::string::npos) {
      findings.push_back(Finding{"Terraform State Exposed", "critical", base + path,
                                 "Terraform state file publicly accessible. "
                                 "Contains ALL infrastructure secrets: AWS keys, database passwords, "
                                 "private keys, and full resource inventory.",
                                 "", path, "terraform_version found in response"});
      return findings;
    }
  }
  return findings;
}

/// HashiCorp Vault/Consul exposed without auth.
std::vector<Finding> scan_vault_consul(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Vault
  auto vault = http.get(base + "/v1/sys/health");
  if (vault.status_code == 200 && vault.body.find("initialized") != std::string::npos && vault.body.find("sealed") != std::string::npos) {
    findings.push_back(Finding{"HashiCorp Vault — Exposed", "high", base + "/v1/sys/health",
                               "Vault health endpoint accessible. Check if unsealed and auth-free.", "", "", vault.body.substr(0, 200)});
  }

  // Consul
  auto consul = http.get(base + "/v1/catalog/services");
  if (consul.status_code == 200 && consul.body.find("{") == 0 && consul.body.size() > 10) {
    findings.push_back(Finding{"HashiCorp Consul — Exposed", "high", base + "/v1/catalog/services",
                               "Consul service catalog accessible without authentication. "
                               "Reveals internal service topology.",
                               "", "", ""});
  }

  return findings;
}

/// AWS-specific misconfigs detectable from outside.
std::vector<Finding> scan_aws_misconfig(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Extract domain for bucket guessing
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

  // Check for exposed Cognito identity pool
  auto resp = http.get(base);
  std::regex cognito_re(R"x(us-east-1:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})x");
  std::smatch m;
  if (std::regex_search(resp.body, m, cognito_re)) {
    findings.push_back(Finding{"AWS Cognito Identity Pool ID Exposed", "medium", base,
                               "Cognito Identity Pool ID found in client-side code: " + m.str() + ". Test for unauthenticated role access.",
                               "", m.str(), ""});
  }

  // Check for exposed AWS region/account in errors
  std::regex aws_arn_re(R"x(arn:aws:[a-z0-9-]+:[a-z0-9-]+:\d{12}:)x");
  if (std::regex_search(resp.body, m, aws_arn_re)) {
    findings.push_back(Finding{"AWS ARN Leaked", "medium", base, "AWS Account ARN exposed in page: " + m.str(), "", m.str(), ""});
  }

  return findings;
}

/// Environment variable / config file exposure in cloud deployments.
std::vector<Finding> scan_cloud_config_leak(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  struct ConfigCheck {
    std::string path;
    std::string indicator;
    std::string name;
  };

  std::vector<ConfigCheck> checks = {
      {"/config.json", "\"database\"", "Config JSON"},
      {"/config.yaml", "database:", "Config YAML"},
      {"/config.yml", "password:", "Config YAML"},
      {"/.env.production", "DB_PASSWORD", "Production Env"},
      {"/.env.staging", "API_KEY", "Staging Env"},
      {"/application.properties", "spring.datasource", "Spring Config"},
      {"/application.yml", "datasource:", "Spring YAML Config"},
      {"/appsettings.json", "ConnectionStrings", ".NET App Settings"},
      {"/web.config", "connectionString", "ASP.NET Web Config"},
      {"/docker-compose.yml", "services:", "Docker Compose"},
      {"/docker-compose.yaml", "environment:", "Docker Compose"},
      {"/.dockerenv", "", "Docker Environment"},
      {"/Dockerfile", "FROM ", "Dockerfile"},
      {"/.github/workflows/deploy.yml", "secrets.", "GitHub Actions"},
      {"/cloudbuild.yaml", "steps:", "GCP Cloud Build"},
      {"/buildspec.yml", "phases:", "AWS CodeBuild"},
  };

  for (const auto& check : checks) {
    auto resp = http.get(base + check.path);
    if (resp.status_code == 200 && resp.body.size() > 20 && resp.body.find("Access Denied") == std::string::npos &&
        resp.body.find("<!DOCTYPE") == std::string::npos && resp.body.find("<HTML>") == std::string::npos) {
      if (check.indicator.empty() || resp.body.find(check.indicator) != std::string::npos) {
        findings.push_back(Finding{check.name + " Exposed", "high", base + check.path,
                                   check.name + " publicly accessible. May contain credentials.", "", check.path,
                                   "Indicator: " + check.indicator});
        if (findings.size() >= 3) return findings;
      }
    }
  }
  return findings;
}

/// CI/CD pipeline exposure.
std::vector<Finding> scan_cicd_exposure(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  struct CICDCheck {
    std::string path;
    std::string indicator;
    std::string name;
  };

  std::vector<CICDCheck> checks = {
      {"/.gitlab-ci.yml", "stages:", "GitLab CI Config"},
      {"/.circleci/config.yml", "jobs:", "CircleCI Config"},
      {"/Jenkinsfile", "pipeline", "Jenkinsfile"},
      {"/.travis.yml", "language:", "Travis CI Config"},
      {"/.github/workflows/ci.yml", "on:", "GitHub Actions CI"},
      {"/bitbucket-pipelines.yml", "pipelines:", "Bitbucket Pipelines"},
      {"/.drone.yml", "kind:", "Drone CI Config"},
  };

  for (const auto& check : checks) {
    auto resp = http.get(base + check.path);
    if (resp.status_code == 200 && resp.body.size() > 30 && resp.body.find(check.indicator) != std::string::npos &&
        resp.body.find("<!DOCTYPE") == std::string::npos && resp.body.find("Access Denied") == std::string::npos) {
      findings.push_back(Finding{check.name + " Exposed", "medium", base + check.path,
                                 check.name + " publicly accessible. "
                                              "Reveals build pipeline, deployment targets, and potentially secrets.",
                                 "", check.path, ""});
    }
  }
  return findings;
}

}  // namespace

std::vector<Scanner> register_cloud_attack_scanners() {
  return {
      {"Docker Registry", scan_docker_registry}, {"Kubernetes Exposed", scan_k8s_exposed}, {"Terraform State", scan_terraform_state},
      {"Vault/Consul", scan_vault_consul},       {"AWS Misconfig", scan_aws_misconfig},    {"Cloud Config Leak", scan_cloud_config_leak},
      {"CI/CD Exposure", scan_cicd_exposure},
  };
}

}  // namespace apex
