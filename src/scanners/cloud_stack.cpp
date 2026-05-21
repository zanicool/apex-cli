/// @file scanners/cloud_stack.cpp
/// @brief Modern cloud stack scanner: Supabase, Firebase, Neon, PlanetScale,
///        Clerk, Auth0, Vercel, Cloudflare, PostHog, Sentry misconfigurations.
///        Detects exposed keys, open APIs, permissive RLS, leaked configs.
#include "scanner_base.hpp"
#include <set>

namespace apex {
namespace {

/// Supabase misconfigurations: exposed anon key, disabled RLS, open storage.
std::vector<Finding> scan_supabase(const Config &, HttpClient &http,
                                   const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Look for Supabase keys in page source.
  std::string supabase_url, anon_key;
  for (const auto &url : crawl.urls) {
    auto resp = http.get(url);
    // NEXT_PUBLIC_SUPABASE_URL / NEXT_PUBLIC_SUPABASE_ANON_KEY
    std::regex url_re(R"(https://[a-z]+\.supabase\.co)");
    std::regex key_re(R"(eyJ[A-Za-z0-9_-]{100,})");
    std::smatch m;
    if (std::regex_search(resp.body, m, url_re)) supabase_url = m[0].str();
    if (std::regex_search(resp.body, m, key_re)) anon_key = m[0].str();
    if (!supabase_url.empty()) break;
  }

  if (supabase_url.empty()) return findings;

  findings.push_back({"Supabase Instance Detected", "info", supabase_url,
                      "Supabase project URL found in client code", "", "", ""});

  if (!anon_key.empty()) {
    // Test if RLS is disabled — try to read tables directly.
    const std::vector<std::string> tables = {
        "users", "profiles", "accounts", "orders", "payments",
        "messages", "documents", "files", "settings", "admin"};

    for (const auto &table : tables) {
      auto resp = http.get(supabase_url + "/rest/v1/" + table + "?select=*&limit=1",
                           {{"apikey", anon_key}, {"Authorization", "Bearer " + anon_key}});
      if (resp.status_code == 200 && resp.body.size() > 5 &&
          resp.body != "[]" && resp.body.find("error") == std::string::npos) {
        findings.push_back({"Supabase RLS Disabled: " + table, "critical",
                            supabase_url + "/rest/v1/" + table,
                            "Table '" + table + "' readable without auth — RLS not enforced",
                            "", "", ""});
      }
    }

    // Check storage buckets.
    auto storage = http.get(supabase_url + "/storage/v1/bucket",
                            {{"apikey", anon_key}, {"Authorization", "Bearer " + anon_key}});
    if (storage.status_code == 200 && storage.body.find("name") != std::string::npos) {
      findings.push_back({"Supabase Storage Buckets Exposed", "high",
                          supabase_url + "/storage/v1/bucket",
                          "Storage buckets listable with anon key", "", "", ""});
    }

    // Check if service_role key is accidentally exposed (catastrophic).
    for (const auto &url : crawl.urls) {
      auto resp = http.get(url);
      if (resp.body.find("service_role") != std::string::npos ||
          resp.body.find("SUPABASE_SERVICE") != std::string::npos) {
        findings.push_back({"Supabase Service Role Key Leaked", "critical", url,
                            "service_role key in client code — full DB admin access",
                            "", "", ""});
        break;
      }
    }
  }
  return findings;
}

/// Clerk/Auth0/auth provider misconfigurations.
std::vector<Finding> scan_auth_providers(const Config &, HttpClient &http,
                                         const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  std::string clerk_key, auth0_domain;
  for (const auto &url : crawl.urls) {
    auto resp = http.get(url);
    // Clerk publishable key.
    if (resp.body.find("pk_live_") != std::string::npos ||
        resp.body.find("pk_test_") != std::string::npos) {
      std::regex re(R"(pk_(live|test)_[A-Za-z0-9]+)");
      std::smatch m;
      if (std::regex_search(resp.body, m, re)) clerk_key = m[0].str();
    }
    // Auth0 domain.
    std::regex auth0_re(R"(([a-z0-9\-]+\.auth0\.com))");
    std::smatch m;
    if (std::regex_search(resp.body, m, auth0_re)) auth0_domain = m[0].str();

    // Check for secret keys accidentally exposed.
    if (resp.body.find("sk_live_") != std::string::npos) {
      findings.push_back({"Clerk Secret Key Leaked", "critical", url,
                          "Clerk secret key (sk_live_) in client-side code", "", "", ""});
    }
    if (resp.body.find("AUTH0_SECRET") != std::string::npos ||
        resp.body.find("auth0_client_secret") != std::string::npos) {
      findings.push_back({"Auth0 Client Secret Leaked", "critical", url,
                          "Auth0 client secret in client-side code", "", "", ""});
    }
  }

  // Test Auth0 management API exposure.
  if (!auth0_domain.empty()) {
    auto resp = http.get("https://" + auth0_domain + "/api/v2/users");
    if (resp.status_code == 200 && resp.body.find("email") != std::string::npos) {
      findings.push_back({"Auth0 Management API Open", "critical",
                          "https://" + auth0_domain + "/api/v2/users",
                          "Auth0 management API accessible without auth", "", "", ""});
    }
  }
  return findings;
}

/// Vercel/Netlify/Cloudflare deployment misconfigs.
std::vector<Finding> scan_deployment_platforms(const Config &, HttpClient &http,
                                               const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // Vercel: exposed _next/data, environment variables in source.
  auto next_resp = http.get(base + "/_next/data/");
  if (next_resp.status_code == 200) {
    findings.push_back({"Vercel _next/data Exposed", "low", base + "/_next/data/",
                        "Next.js data directory listable", "", "", ""});
  }

  // Check for exposed .vercel, .netlify configs.
  for (const auto &path : {"/.vercel/project.json", "/.netlify/state.json"}) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 && resp.body.size() > 10) {
      findings.push_back({"Deployment Config Exposed", "medium", base + path,
                          "Platform deployment config accessible", "", "", ""});
    }
  }

  // Cloudflare: check for exposed Workers KV, D1, R2.
  for (const auto &url : crawl.urls) {
    auto resp = http.get(url);
    if (resp.body.find("CLOUDFLARE_API_TOKEN") != std::string::npos ||
        resp.body.find("CF_API_KEY") != std::string::npos) {
      findings.push_back({"Cloudflare API Token Leaked", "critical", url,
                          "Cloudflare API token in source code", "", "", ""});
    }
  }

  // Check for exposed preview deployments with different env vars.
  auto preview = http.get(base, {{"X-Vercel-Protection-Bypass", ""}});
  if (preview.status_code == 200 && preview.body != http.get(base).body) {
    findings.push_back({"Vercel Preview Bypass", "medium", base,
                        "Preview deployment accessible via header bypass", "", "", ""});
  }
  return findings;
}

/// Serverless DB misconfigs: Neon, PlanetScale, Turso, Upstash.
std::vector<Finding> scan_serverless_db(const Config &, HttpClient &http,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  // Scan for leaked connection strings in source.
  const std::vector<std::pair<std::string, std::string>> patterns = {
      {"postgres://", "PostgreSQL connection string (Neon/Supabase/PlanetScale)"},
      {"mysql://", "MySQL connection string (PlanetScale)"},
      {"libsql://", "Turso/LibSQL connection string"},
      {"redis://", "Redis/Upstash connection string"},
      {"rediss://", "Redis TLS connection string (Upstash)"},
      {"mongodb+srv://", "MongoDB Atlas connection string"},
      {"NEON_DATABASE_URL", "Neon DB URL variable"},
      {"DATABASE_URL", "Database URL variable"},
      {"TURSO_AUTH_TOKEN", "Turso auth token"},
      {"UPSTASH_REDIS_REST_URL", "Upstash Redis URL"},
  };

  for (const auto &url : crawl.urls) {
    auto resp = http.get(url);
    for (const auto &[pattern, desc] : patterns) {
      if (resp.body.find(pattern) != std::string::npos) {
        // Verify it's not just a placeholder/docs reference.
        size_t pos = resp.body.find(pattern);
        std::string context = resp.body.substr(pos, std::min(size_t(100), resp.body.size() - pos));
        if (context.find("example") == std::string::npos &&
            context.find("placeholder") == std::string::npos &&
            context.find("YOUR_") == std::string::npos) {
          findings.push_back({"Leaked DB Credential: " + desc, "critical", url,
                              desc + " found in client-accessible code", "", "", ""});
        }
      }
    }
  }
  return findings;
}

/// Observability/analytics misconfigs: PostHog, Sentry, Datadog.
std::vector<Finding> scan_observability(const Config &, HttpClient &http,
                                        const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  // PostHog: check for exposed API with overly permissive project key.
  for (const auto &url : crawl.urls) {
    auto resp = http.get(url);
    std::regex ph_re(R"(phc_[A-Za-z0-9]{20,})");
    std::smatch m;
    if (std::regex_search(resp.body, m, ph_re)) {
      std::string key = m[0].str();
      // Test if we can query events (should be write-only).
      auto test = http.get("https://app.posthog.com/api/event/?token=" + key);
      if (test.status_code == 200 && test.body.find("results") != std::string::npos) {
        findings.push_back({"PostHog API Key Overpermissioned", "high",
                            "https://app.posthog.com/api/event/",
                            "PostHog key allows reading events — should be write-only",
                            "", key, ""});
      }
    }

    // Sentry DSN — check if it leaks internal project info.
    std::regex sentry_re(R"(https://[a-f0-9]+@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+)");
    if (std::regex_search(resp.body, m, sentry_re)) {
      findings.push_back({"Sentry DSN Exposed", "info", url,
                          "Sentry DSN in source — normal for client-side, verify scope",
                          "", m[0].str(), ""});
    }
  }

  // Check for exposed Grafana/monitoring dashboards.
  for (const auto &path : {"/grafana/", "/kibana/", "/prometheus/", "/jaeger/"}) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 && resp.body.size() > 200 &&
        resp.body.find("login") == std::string::npos) {
      findings.push_back({"Exposed Monitoring: " + std::string(path), "high",
                          base + path, "Monitoring dashboard accessible without auth",
                          "", "", ""});
    }
  }
  return findings;
}

/// Realtime/messaging misconfigs: Pusher, Ably, WebSocket endpoints.
std::vector<Finding> scan_realtime_infra(const Config &, HttpClient &http,
                                         const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;

  for (const auto &url : crawl.urls) {
    auto resp = http.get(url);

    // Pusher keys — check if they allow subscribing to private channels.
    std::regex pusher_re(R"(([a-f0-9]{20}))");
    if (resp.body.find("pusher") != std::string::npos ||
        resp.body.find("Pusher") != std::string::npos) {
      if (resp.body.find("pusherSecret") != std::string::npos ||
          resp.body.find("PUSHER_SECRET") != std::string::npos) {
        findings.push_back({"Pusher Secret Key Leaked", "critical", url,
                            "Pusher secret in client code — can forge auth for private channels",
                            "", "", ""});
      }
    }

    // Ably API key.
    std::regex ably_re(R"([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+:[A-Za-z0-9_-]+)");
    std::smatch m;
    if (resp.body.find("ably") != std::string::npos &&
        std::regex_search(resp.body, m, ably_re)) {
      findings.push_back({"Ably API Key Exposed", "high", url,
                          "Ably key in source — verify it's subscribe-only",
                          "", "", ""});
    }

    // Exposed WebSocket endpoints without auth.
    std::regex ws_re(R"(wss?://[^\s"']+)");
    auto begin = std::sregex_iterator(resp.body.begin(), resp.body.end(), ws_re);
    auto end = std::sregex_iterator();
    for (auto it = begin; it != end; ++it) {
      std::string ws_url = (*it)[0].str();
      if (ws_url.find("socket") != std::string::npos ||
          ws_url.find("ws.") != std::string::npos) {
        findings.push_back({"WebSocket Endpoint Found", "info", ws_url,
                            "WebSocket endpoint in source — verify auth requirements",
                            "", "", ""});
        break;
      }
    }
  }
  return findings;
}

/// Automation/low-code misconfigs: n8n, Retool, internal tools.
std::vector<Finding> scan_automation_tools(const Config &, HttpClient &http,
                                           const CrawlResult &crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  const std::vector<std::pair<std::string, std::string>> paths = {
      {"/n8n/", "n8n workflow automation"},
      {"/webhook/", "Webhook endpoint"},
      {"/api/webhooks", "Webhooks API"},
      {"/retool/", "Retool admin panel"},
      {"/tooljet/", "ToolJet admin"},
      {"/budibase/", "Budibase admin"},
      {"/backstage/", "Backstage developer portal"},
      {"/langfuse/", "LangFuse AI observability"},
      {"/api/v1/workflows", "Workflow API"},
  };

  for (const auto &[path, name] : paths) {
    auto resp = http.get(base + path);
    if (resp.status_code == 200 && resp.body.size() > 100 &&
        resp.body.find("unauthorized") == std::string::npos &&
        resp.body.find("login") == std::string::npos) {
      findings.push_back({"Exposed " + name, "high", base + path,
                          name + " accessible without authentication", "", "", ""});
    }
  }
  return findings;
}

} // namespace

std::vector<Scanner> register_cloud_stack_scanners() {
  return {
      {"Supabase Misconfig", scan_supabase},
      {"Auth Providers (Clerk/Auth0)", scan_auth_providers},
      {"Deployment Platforms", scan_deployment_platforms},
      {"Serverless DB Leaks", scan_serverless_db},
      {"Observability Misconfig", scan_observability},
      {"Realtime Infra", scan_realtime_infra},
      {"Automation Tools", scan_automation_tools},
  };
}

} // namespace apex
