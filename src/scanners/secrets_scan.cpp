/// @file scanners/secrets_scan.cpp
/// @brief Deep secrets scanner: exposed .env, git repos, Docker registry,
///        CI/CD artifacts, config files, backup files with credentials.
#include "scanner_base.hpp"
#include <set>

namespace apex {
namespace {

std::vector<Finding> scan_exposed_env(const Config &, HttpClient &http,
                                      const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> paths = {
      "/.env", "/.env.local", "/.env.production", "/.env.staging",
      "/.env.development", "/.env.backup", "/.env.old", "/.env.bak",
      "/config.yml", "/config.yaml", "/config.json", "/config.toml",
      "/application.yml", "/application.properties",
      "/wp-config.php.bak", "/wp-config.php.old", "/wp-config.php~",
      "/settings.py", "/local_settings.py",
      "/.docker/config.json", "/docker-compose.yml",
      "/appsettings.json", "/appsettings.Development.json",
      "/.npmrc", "/.pypirc", "/.gem/credentials",
  };

  const std::vector<std::string> secret_indicators = {
      "PASSWORD", "SECRET", "API_KEY", "TOKEN", "PRIVATE_KEY",
      "AWS_ACCESS", "DATABASE_URL", "MONGO_URI", "REDIS_URL",
      "SMTP_PASS", "SENDGRID", "STRIPE", "TWILIO", "password:",
      "secret_key", "client_secret", "-----BEGIN"};

  for (const auto &path : paths) {
    auto resp = http.get(base + path);
    if (resp.status_code != 200 || resp.body.size() < 10) continue;
    for (const auto &indicator : secret_indicators) {
      if (resp.body.find(indicator) != std::string::npos) {
        findings.push_back({"Exposed Secrets File", "critical", base + path,
                            "File contains credentials/secrets (found: " + indicator + ")",
                            "", "", ""});
        break;
      }
    }
  }
  return findings;
}

std::vector<Finding> scan_git_exposure(const Config &, HttpClient &http,
                                       const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Check for exposed .git directory.
  auto resp = http.get(base + "/.git/HEAD");
  if (resp.status_code == 200 && resp.body.find("ref:") != std::string::npos) {
    findings.push_back({"Git Repository Exposed", "critical", base + "/.git/",
                        "Full git repository accessible — source code + history downloadable",
                        "", "", ""});

    // Try to get config for more info.
    auto cfg_resp = http.get(base + "/.git/config");
    if (cfg_resp.status_code == 200 &&
        (cfg_resp.body.find("token") != std::string::npos ||
         cfg_resp.body.find("password") != std::string::npos)) {
      findings.push_back({"Git Config Secrets", "critical", base + "/.git/config",
                          "Git config contains credentials", "", "", ""});
    }
  }

  // SVN.
  auto svn = http.get(base + "/.svn/entries");
  if (svn.status_code == 200 && svn.body.size() > 10) {
    findings.push_back({"SVN Repository Exposed", "high", base + "/.svn/",
                        "SVN repository accessible", "", "", ""});
  }

  // Mercurial.
  auto hg = http.get(base + "/.hg/store/00manifest.i");
  if (hg.status_code == 200 && hg.body.size() > 10) {
    findings.push_back({"Mercurial Repository Exposed", "high", base + "/.hg/",
                        "Mercurial repository accessible", "", "", ""});
  }
  return findings;
}

std::vector<Finding> scan_docker_registry(const Config &cfg, HttpClient &http,
                                          const CrawlResult &) {
  std::vector<Finding> findings;
  std::string domain = cfg.target;
  if (domain.find("://") != std::string::npos)
    domain = domain.substr(domain.find("://") + 3);
  if (domain.find('/') != std::string::npos)
    domain = domain.substr(0, domain.find('/'));

  // Check for exposed Docker registry.
  const std::vector<std::string> registry_hosts = {
      "https://" + domain + ":5000",
      "https://registry." + domain,
      "http://" + domain + ":5000",
  };

  for (const auto &host : registry_hosts) {
    auto resp = http.get(host + "/v2/_catalog");
    if (resp.status_code == 200 && resp.body.find("repositories") != std::string::npos) {
      findings.push_back({"Docker Registry Exposed", "critical", host + "/v2/_catalog",
                          "Docker registry publicly accessible — images can be pulled/inspected",
                          "", "", ""});
    }
  }
  return findings;
}

std::vector<Finding> scan_cicd_artifacts(const Config &, HttpClient &http,
                                         const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::pair<std::string, std::string>> paths = {
      {"/.github/workflows/", "GitHub Actions workflows"},
      {"/.gitlab-ci.yml", "GitLab CI config"},
      {"/Jenkinsfile", "Jenkins pipeline"},
      {"/.circleci/config.yml", "CircleCI config"},
      {"/.travis.yml", "Travis CI config"},
      {"/bitbucket-pipelines.yml", "Bitbucket Pipelines"},
      {"/.drone.yml", "Drone CI config"},
      {"/Dockerfile", "Dockerfile"},
      {"/docker-compose.yml", "Docker Compose"},
      {"/terraform.tfstate", "Terraform state (CRITICAL)"},
      {"/terraform.tfvars", "Terraform variables"},
      {"/.terraform/", "Terraform directory"},
      {"/ansible/vault.yml", "Ansible vault"},
      {"/k8s/secrets.yaml", "Kubernetes secrets"},
  };

  for (const auto &[path, name] : paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 && resp.body.size() > 20) {
      std::string severity = "medium";
      if (name.find("CRITICAL") != std::string::npos ||
          resp.body.find("SECRET") != std::string::npos ||
          resp.body.find("password") != std::string::npos ||
          resp.body.find("token") != std::string::npos)
        severity = "critical";
      findings.push_back({"CI/CD Artifact Exposed: " + name, severity, base + path,
                          name + " publicly accessible", "", "", ""});
    }
  }
  return findings;
}

std::vector<Finding> scan_backup_files(const Config &, HttpClient &http,
                                       const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> paths = {
      "/backup.sql", "/backup.sql.gz", "/dump.sql", "/db.sql",
      "/database.sql", "/backup.tar.gz", "/backup.zip",
      "/site.tar.gz", "/www.zip", "/public.zip",
      "/backup/", "/backups/", "/_backup/",
      "/old/", "/temp/", "/tmp/",
  };

  for (const auto &path : paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 && resp.body.size() > 100) {
      findings.push_back({"Backup File Exposed", "high", base + path,
                          "Backup/dump file publicly accessible",
                          "", "", ""});
    }
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_secrets_scanners() {
  return {
      {"Exposed .env/Config", scan_exposed_env},
      {"Git Repository Exposure", scan_git_exposure},
      {"Docker Registry", scan_docker_registry},
      {"CI/CD Artifacts", scan_cicd_artifacts},
      {"Backup Files", scan_backup_files},
  };
}

} // namespace apex
