/// @file src/profile_generator.cpp
/// @brief Auto-learning ZAP profile generator. When a new framework/CMS is
///        detected that has no existing profile, generates one from scan intel.
///        Profiles accumulate over time — the system learns from each scan.
#include "profile_generator.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <sstream>

namespace apex {

namespace fs = std::filesystem;

ProfileGenerator::ProfileGenerator(const std::string& profiles_dir) : profiles_dir_(profiles_dir) {
  fs::create_directories(profiles_dir_);
  load_known_profiles();
}

void ProfileGenerator::load_known_profiles() {
  if (!fs::exists(profiles_dir_)) return;
  for (const auto& entry : fs::directory_iterator(profiles_dir_)) {
    if (entry.is_directory()) {
      known_profiles_.insert(entry.path().filename().string());
    }
  }
}

bool ProfileGenerator::has_profile(const std::string& framework) const { return known_profiles_.count(normalize(framework)) > 0; }

std::string ProfileGenerator::normalize(const std::string& name) {
  std::string result;
  for (char c : name) {
    if (c == ' ' || c == '/')
      result += '-';
    else
      result += std::tolower(c);
  }
  return result;
}

std::string ProfileGenerator::generate_profile(const std::string& framework, const ScanIntel& intel) {
  std::string slug = normalize(framework);
  std::string dir = profiles_dir_ + "/" + slug;
  fs::create_directories(dir);

  // Generate scan.yaml
  std::string scan_path = dir + "/scan.yaml";
  std::ofstream scan(scan_path);
  scan << "---\n";
  scan << "# Auto-generated ZAP profile for: " << framework << "\n";
  scan << "# Generated: " << intel.scan_date << "\n";
  scan << "# Source: apex-cli auto-learning from scan of " << intel.target << "\n";
  scan << "#\n";
  scan << "# This profile was created automatically when apex-cli detected\n";
  scan << "# " << framework << " without an existing scan profile.\n";
  scan << "# It will be refined on subsequent scans.\n";
  scan << "#\n";
  scan << "env:\n";
  scan << "  contexts:\n";
  scan << "    - name: \"" << framework << " Target\"\n";
  scan << "      urls:\n";
  scan << "        - \"${target.url}\"\n";
  scan << "      includePaths:\n";
  scan << "        - \"${target.url}.*\"\n";
  scan << "      excludePaths:\n";
  scan << "        - \".*\\\\.js$\"\n";
  scan << "        - \".*\\\\.css$\"\n";
  scan << "        - \".*\\\\.png$\"\n";
  scan << "        - \".*\\\\.jpg$\"\n";
  scan << "        - \".*\\\\.woff2?$\"\n";
  scan << "\njobs:\n";

  // Spider.
  scan << "  - type: spider\n";
  scan << "    parameters:\n";
  scan << "      maxDuration: 5\n";
  scan << "      maxDepth: 5\n";
  scan << "      url: \"${target.url}\"\n";

  // AJAX spider if SPA detected.
  if (intel.is_spa) {
    scan << "  - type: spiderAjax\n";
    scan << "    parameters:\n";
    scan << "      maxDuration: 3\n";
    scan << "      maxCrawlDepth: 3\n";
  }

  // Requestor with discovered endpoints.
  if (!intel.interesting_paths.empty()) {
    scan << "  - type: requestor\n";
    scan << "    requests:\n";
    for (const auto& path : intel.interesting_paths) {
      scan << "      - url: \"${target.url}" << path << "\"\n";
    }
  }

  // Active scan with targeted policy.
  scan << "  - type: activeScan\n";
  scan << "    parameters:\n";
  scan << "      maxRuleDurationInMins: 5\n";
  scan << "      maxScanDurationInMins: 20\n";
  scan << "      policy: \"policy.yaml\"\n";

  // Report.
  scan << "  - type: report\n";
  scan << "    parameters:\n";
  scan << "      template: \"traditional-json\"\n";
  scan << "      reportDir: \"/tmp/zap-reports\"\n";
  scan << "      reportFile: \"" << slug << "-scan\"\n";
  scan << "    risks:\n";
  scan << "      - high\n";
  scan << "      - medium\n";
  scan << "      - low\n";
  scan.close();

  // Generate policy.yaml based on detected attack surface.
  std::string policy_path = dir + "/policy.yaml";
  std::ofstream policy(policy_path);
  policy << "---\n";
  policy << "# Auto-generated scan policy for: " << framework << "\n";
  policy << "name: \"" << framework << " Policy\"\n\n";
  policy << "rules:\n";

  // Always enable core rules.
  policy << "  # SQL Injection\n";
  policy << "  - id: 40018\n";
  policy << "    strength: HIGH\n";
  policy << "    threshold: MEDIUM\n";
  policy << "  # XSS Reflected\n";
  policy << "  - id: 40012\n";
  policy << "    strength: HIGH\n";
  policy << "    threshold: MEDIUM\n";
  policy << "  # XSS Persistent\n";
  policy << "  - id: 40014\n";
  policy << "    strength: HIGH\n";
  policy << "    threshold: MEDIUM\n";

  // Add rules based on what we found.
  if (intel.has_forms) {
    policy << "  # CSRF\n";
    policy << "  - id: 40014\n";
    policy << "    strength: HIGH\n";
    policy << "    threshold: MEDIUM\n";
  }
  if (intel.has_api) {
    policy << "  # SSRF\n";
    policy << "  - id: 40046\n";
    policy << "    strength: HIGH\n";
    policy << "    threshold: MEDIUM\n";
    policy << "  # Command Injection\n";
    policy << "  - id: 90020\n";
    policy << "    strength: HIGH\n";
    policy << "    threshold: MEDIUM\n";
  }
  if (intel.has_file_upload) {
    policy << "  # Path Traversal\n";
    policy << "  - id: 6\n";
    policy << "    strength: HIGH\n";
    policy << "    threshold: MEDIUM\n";
    policy << "  # Remote File Inclusion\n";
    policy << "  - id: 7\n";
    policy << "    strength: HIGH\n";
    policy << "    threshold: MEDIUM\n";
  }
  if (intel.has_auth) {
    policy << "  # Authentication bypass\n";
    policy << "  - id: 10101\n";
    policy << "    strength: HIGH\n";
    policy << "    threshold: MEDIUM\n";
  }

  // Disable irrelevant rules.
  if (!intel.has_ldap) {
    policy << "  # LDAP Injection — disabled (not detected)\n";
    policy << "  - id: 40015\n";
    policy << "    strength: OFF\n";
    policy << "    threshold: OFF\n";
  }
  policy.close();

  // Generate urls.txt with discovered paths.
  std::string urls_path = dir + "/urls.txt";
  std::ofstream urls(urls_path);
  urls << "# Auto-discovered paths for " << framework << "\n";
  urls << "# From scan of " << intel.target << " on " << intel.scan_date << "\n";
  for (const auto& path : intel.interesting_paths) {
    urls << path << "\n";
  }
  urls.close();

  // Track this profile.
  known_profiles_.insert(slug);

  std::cout << "  -> New ZAP profile generated: profiles/" << slug << "/\n";
  std::cout << "     (scan.yaml, policy.yaml, urls.txt)\n";
  return dir;
}

void ProfileGenerator::update_profile(const std::string& framework, const ScanIntel& intel) {
  std::string slug = normalize(framework);
  std::string urls_path = profiles_dir_ + "/" + slug + "/urls.txt";

  // Append new paths to urls.txt (learning).
  std::set<std::string> existing;
  if (fs::exists(urls_path)) {
    std::ifstream in(urls_path);
    std::string line;
    while (std::getline(in, line)) {
      if (!line.empty() && line[0] != '#') existing.insert(line);
    }
  }

  int added = 0;
  std::ofstream out(urls_path, std::ios::app);
  for (const auto& path : intel.interesting_paths) {
    if (existing.insert(path).second) {
      out << path << "\n";
      added++;
    }
  }
  out.close();

  if (added > 0) {
    std::cout << "  -> Updated profile '" << slug << "': +" << added << " new paths\n";
  }
}

ScanIntel ProfileGenerator::build_intel(const std::string& target, const CrawlResult& crawl, const std::vector<Finding>& findings) {
  ScanIntel intel;
  intel.target = target;

  // Get current date.
  auto now = std::chrono::system_clock::now();
  auto t = std::chrono::system_clock::to_time_t(now);
  char buf[32];
  std::strftime(buf, sizeof(buf), "%Y-%m-%d", std::localtime(&t));
  intel.scan_date = buf;

  // Analyze crawl results.
  intel.has_forms = !crawl.forms.empty();
  intel.has_api = false;
  intel.has_auth = false;
  intel.has_file_upload = false;
  intel.has_ldap = false;
  intel.is_spa = false;

  for (const auto& url : crawl.urls) {
    if (url.find("/api/") != std::string::npos || url.find("/v1/") != std::string::npos) intel.has_api = true;
    if (url.find("login") != std::string::npos || url.find("auth") != std::string::npos) intel.has_auth = true;
  }

  // Analyze findings for intel.
  for (const auto& f : findings) {
    if (f.type == "File Upload Found") intel.has_file_upload = true;
    if (f.type.find("LDAP") != std::string::npos) intel.has_ldap = true;
    if (f.type.find("SPA") != std::string::npos || f.detail.find("React") != std::string::npos ||
        f.detail.find("Angular") != std::string::npos || f.detail.find("Vue") != std::string::npos ||
        f.detail.find("Next") != std::string::npos)
      intel.is_spa = true;

    // Collect interesting paths from findings.
    if (!f.url.empty() && f.url.find(target) != std::string::npos) {
      size_t path_start = f.url.find('/', f.url.find("://") + 3);
      if (path_start != std::string::npos) {
        std::string path = f.url.substr(path_start);
        if (path.size() > 1 && path.size() < 100) intel.interesting_paths.push_back(path);
      }
    }
  }

  // Deduplicate paths.
  std::set<std::string> unique(intel.interesting_paths.begin(), intel.interesting_paths.end());
  intel.interesting_paths.assign(unique.begin(), unique.end());

  return intel;
}

}  // namespace apex
