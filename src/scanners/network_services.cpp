/// @file scanners/network_services.cpp
/// @brief Network service exposure: Prometheus, Grafana, RabbitMQ, Nginx status,
///        Apache mod_status, Swagger UI, Kubernetes metrics, etcd, Zookeeper,
///        Memcached, Webpack bundle analyzer, Storybook.
#include "scanner_base.hpp"

namespace apex {
namespace {

/// Exposed Prometheus metrics — process_ indicators leak internal runtime data.
std::vector<Finding> scan_prometheus_metrics(const Config &, HttpClient &http,
                                             const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> paths = {"/metrics", "/-/metrics",
                                           "/prometheus/metrics"};
  for (const auto &path : paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 &&
        resp.body.find("process_") != std::string::npos &&
        resp.body.find("# HELP") != std::string::npos) {
      findings.push_back({"Exposed Prometheus Metrics", "high", base + path,
                          "Prometheus metrics endpoint publicly accessible. "
                          "Leaks process info, memory usage, and internal service names.",
                          "", "", resp.body.substr(0, 400)});
    }
  }
  return findings;
}

/// Exposed Grafana without authentication — dashboards accessible.
std::vector<Finding> scan_grafana_unauth(const Config &, HttpClient &http,
                                         const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> paths = {"/api/dashboards/home",
                                           "/grafana/api/dashboards/home"};
  for (const auto &path : paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 &&
        resp.body.find("\"dashboard\"") != std::string::npos) {
      findings.push_back({"Exposed Grafana (No Auth)", "high", base + path,
                          "Grafana instance accessible without authentication. "
                          "Exposes internal metrics, infrastructure topology, and "
                          "potentially sensitive business data.",
                          "", "", resp.body.substr(0, 300)});
    }
  }
  return findings;
}

/// RabbitMQ management interface exposed without proper access control.
std::vector<Finding> scan_rabbitmq_management(const Config &, HttpClient &http,
                                              const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> paths = {"/api/overview",
                                           "/rabbitmq/api/overview"};
  for (const auto &path : paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 &&
        resp.body.find("rabbitmq_version") != std::string::npos) {
      findings.push_back({"RabbitMQ Management Exposed", "high", base + path,
                          "RabbitMQ management API accessible. Reveals version, "
                          "queue names, message rates, and cluster configuration.",
                          "", "", resp.body.substr(0, 300)});
    }
  }
  return findings;
}

/// Nginx stub_status module exposed — reveals connection statistics.
std::vector<Finding> scan_nginx_status(const Config &, HttpClient &http,
                                       const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> paths = {"/nginx_status", "/status",
                                           "/nginx-status", "/stub_status"};
  for (const auto &path : paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 &&
        resp.body.find("Active connections") != std::string::npos) {
      findings.push_back({"Nginx Status Exposed", "medium", base + path,
                          "Nginx stub_status module publicly accessible. "
                          "Reveals active connections, request rates, and server load.",
                          "", "", resp.body.substr(0, 200)});
    }
  }
  return findings;
}

/// Apache mod_status exposed — reveals detailed server activity.
std::vector<Finding> scan_apache_mod_status(const Config &, HttpClient &http,
                                            const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> paths = {"/server-status", "/server-info",
                                           "/status", "/apache-status"};
  for (const auto &path : paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 &&
        resp.body.find("Total Accesses") != std::string::npos) {
      findings.push_back({"Apache mod_status Exposed", "medium", base + path,
                          "Apache mod_status publicly accessible. Reveals "
                          "request details, client IPs, virtual hosts, and "
                          "worker thread activity.",
                          "", "", resp.body.substr(0, 400)});
    }
  }
  return findings;
}

/// Exposed Swagger UI or API documentation — reveals full API surface.
std::vector<Finding> scan_swagger_ui(const Config &, HttpClient &http,
                                     const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> paths = {
      "/swagger-ui/", "/swagger-ui/index.html", "/api-docs",
      "/api-docs/", "/swagger.json", "/v2/api-docs",
      "/v3/api-docs", "/swagger/index.html"};
  for (const auto &path : paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 &&
        resp.body.find("swagger") != std::string::npos) {
      findings.push_back({"Exposed Swagger UI", "medium", base + path,
                          "Swagger/OpenAPI documentation publicly accessible. "
                          "Reveals all API endpoints, parameters, and data models.",
                          "", "", resp.body.substr(0, 300)});
      break;  // One finding per target is sufficient.
    }
  }
  return findings;
}

/// Exposed Kubernetes metrics — reveals cluster internals.
std::vector<Finding> scan_kubernetes_metrics(const Config &, HttpClient &http,
                                             const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> paths = {"/metrics", "/api/v1/nodes",
                                           "/apis", "/healthz"};
  for (const auto &path : paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 &&
        resp.body.find("kubernetes") != std::string::npos) {
      findings.push_back({"Exposed Kubernetes Metrics", "critical", base + path,
                          "Kubernetes metrics or API endpoint publicly reachable. "
                          "May expose pod names, namespaces, service accounts, "
                          "and cluster topology.",
                          "", "", resp.body.substr(0, 400)});
    }
  }
  return findings;
}

/// Exposed etcd — key-value store with potential secrets.
std::vector<Finding> scan_etcd_exposed(const Config &, HttpClient &http,
                                       const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> paths = {"/v2/keys", "/v2/keys/",
                                           "/v2/members", "/version"};
  for (const auto &path : paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 &&
        (resp.body.find("\"nodes\"") != std::string::npos ||
         resp.body.find("\"key\"") != std::string::npos ||
         resp.body.find("etcdserver") != std::string::npos)) {
      findings.push_back({"Exposed etcd", "critical", base + path,
                          "etcd key-value store publicly accessible. "
                          "May contain secrets, certificates, and service "
                          "configuration data.",
                          "", "", resp.body.substr(0, 400)});
    }
  }
  return findings;
}

/// Exposed Zookeeper — 4-letter command responses.
std::vector<Finding> scan_zookeeper_exposed(const Config &, HttpClient &http,
                                            const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Zookeeper often exposed via HTTP admin or proxied endpoints.
  const std::vector<std::string> paths = {"/commands", "/commands/stat",
                                           "/commands/conf", "/commands/envi"};
  for (const auto &path : paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 &&
        (resp.body.find("zk_version") != std::string::npos ||
         resp.body.find("Zookeeper") != std::string::npos ||
         resp.body.find("\"command\"") != std::string::npos)) {
      findings.push_back({"Exposed Zookeeper", "critical", base + path,
                          "Zookeeper admin commands accessible. Reveals cluster "
                          "state, connected clients, and configuration. "
                          "4-letter commands may allow reconfiguration.",
                          "", "", resp.body.substr(0, 300)});
    }
  }
  return findings;
}

/// Exposed Memcached — stats response leaks cache internals.
std::vector<Finding> scan_memcached_exposed(const Config &, HttpClient &http,
                                            const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Some Memcached instances are proxied via HTTP or exposed through admin UIs.
  const std::vector<std::string> paths = {"/memcached", "/memcached/stats",
                                           "/stats", "/admin/memcached"};
  for (const auto &path : paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 &&
        (resp.body.find("STAT") != std::string::npos ||
         resp.body.find("bytes_read") != std::string::npos ||
         resp.body.find("curr_connections") != std::string::npos)) {
      findings.push_back({"Exposed Memcached", "high", base + path,
                          "Memcached stats endpoint publicly accessible. "
                          "Reveals cache hit rates, memory usage, and stored "
                          "item counts. May allow cache extraction.",
                          "", "", resp.body.substr(0, 300)});
    }
  }
  return findings;
}

/// Exposed Webpack Bundle Analyzer — reveals full dependency tree.
std::vector<Finding> scan_webpack_analyzer(const Config &, HttpClient &http,
                                           const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> paths = {"/report.html", "/bundle-report.html",
                                           "/stats.json", "/webpack-stats.json",
                                           "/bundle-analyzer"};
  for (const auto &path : paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 &&
        (resp.body.find("webpack") != std::string::npos ||
         resp.body.find("bundleSize") != std::string::npos ||
         resp.body.find("\"modules\"") != std::string::npos)) {
      findings.push_back({"Exposed Webpack Bundle Analyzer", "low", base + path,
                          "Webpack bundle analyzer or stats file publicly "
                          "accessible. Reveals all JavaScript dependencies, "
                          "internal module structure, and bundle composition.",
                          "", "", resp.body.substr(0, 300)});
    }
  }
  return findings;
}

/// Exposed Storybook instance — reveals UI component library.
std::vector<Finding> scan_storybook_exposed(const Config &, HttpClient &http,
                                            const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::string> paths = {"/storybook/", "/storybook/index.html",
                                           "/__storybook/", "/stories/"};
  for (const auto &path : paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 &&
        (resp.body.find("storybook") != std::string::npos ||
         resp.body.find("@storybook") != std::string::npos ||
         resp.body.find("__STORYBOOK") != std::string::npos)) {
      findings.push_back({"Exposed Storybook Instance", "low", base + path,
                          "Storybook component library publicly accessible. "
                          "Reveals internal UI components, prop structures, "
                          "and may expose internal API endpoints in stories.",
                          "", "", resp.body.substr(0, 300)});
    }
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_network_service_scanners() {
  return {
      {"Prometheus Metrics", scan_prometheus_metrics},
      {"Grafana Unauth", scan_grafana_unauth},
      {"RabbitMQ Management", scan_rabbitmq_management},
      {"Nginx Status", scan_nginx_status},
      {"Apache mod_status", scan_apache_mod_status},
      {"Swagger UI", scan_swagger_ui},
      {"Kubernetes Metrics", scan_kubernetes_metrics},
      {"etcd Exposed", scan_etcd_exposed},
      {"Zookeeper Exposed", scan_zookeeper_exposed},
      {"Memcached Exposed", scan_memcached_exposed},
      {"Webpack Bundle Analyzer", scan_webpack_analyzer},
      {"Storybook Exposed", scan_storybook_exposed},
  };
}

} // namespace apex
