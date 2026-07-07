/// @file checkpoint.cpp
/// @brief Scan Checkpoint Engine implementation.
#include "checkpoint.hpp"

#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace fs = std::filesystem;

namespace apex {

namespace {

std::string sanitize_target(const std::string& target) {
  std::string safe = target;
  for (auto& c : safe) {
    if (c == '/' || c == ':' || c == '\\' || c == '?' || c == '&' || c == '=' || c == ' ') c = '_';
  }
  return safe;
}

std::string now_timestamp() {
  auto now = std::chrono::system_clock::now();
  auto t = std::chrono::system_clock::to_time_t(now);
  char buf[32];
  std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
  return std::string(buf);
}

std::string phase_name(ScanPhase phase) {
  switch (phase) {
    case ScanPhase::INIT:
      return "init";
    case ScanPhase::RECON_COMPLETE:
      return "recon_complete";
    case ScanPhase::CRAWL_COMPLETE:
      return "crawl_complete";
    case ScanPhase::PROFILE_COMPLETE:
      return "profile_complete";
    case ScanPhase::SCANNING:
      return "scanning";
    case ScanPhase::SCAN_COMPLETE:
      return "scan_complete";
    case ScanPhase::VERIFICATION:
      return "verification";
    case ScanPhase::REASONING:
      return "reasoning";
    case ScanPhase::REPORT:
      return "report";
    case ScanPhase::COMPLETED:
      return "completed";
  }
  return "unknown";
}

ScanPhase parse_phase(const std::string& s) {
  if (s == "recon_complete") return ScanPhase::RECON_COMPLETE;
  if (s == "crawl_complete") return ScanPhase::CRAWL_COMPLETE;
  if (s == "profile_complete") return ScanPhase::PROFILE_COMPLETE;
  if (s == "scanning") return ScanPhase::SCANNING;
  if (s == "scan_complete") return ScanPhase::SCAN_COMPLETE;
  if (s == "verification") return ScanPhase::VERIFICATION;
  if (s == "reasoning") return ScanPhase::REASONING;
  if (s == "report") return ScanPhase::REPORT;
  if (s == "completed") return ScanPhase::COMPLETED;
  return ScanPhase::INIT;
}

}  // namespace

std::string session_dir(const std::string& target) { return ".apex/sessions/" + sanitize_target(target); }

void save_checkpoint(const ScanSession& session) {
  std::string dir = session_dir(session.target);
  fs::create_directories(dir);
  fs::create_directories(dir + "/evidence");

  // Save state.json
  std::ofstream state(dir + "/state.json");
  if (!state.is_open()) return;

  state << "{\n";
  state << "  \"target\": \"" << session.target << "\",\n";
  state << "  \"session_id\": \"" << session.session_id << "\",\n";
  state << "  \"start_time\": \"" << session.start_time << "\",\n";
  state << "  \"phase\": \"" << phase_name(session.phase) << "\",\n";
  state << "  \"modules_completed\": " << session.modules_completed << ",\n";
  state << "  \"modules_total\": " << session.modules_total << ",\n";
  state << "  \"last_module\": \"" << session.last_module << "\",\n";
  state << "  \"total_requests\": " << session.total_requests << ",\n";
  state << "  \"finding_count\": " << session.findings.size() << ",\n";
  state << "  \"interrupted\": true\n";
  state << "}\n";
  state.close();

  // Save crawled URLs
  std::ofstream crawl_file(dir + "/crawl.json");
  if (crawl_file.is_open()) {
    crawl_file << "[\n";
    for (size_t i = 0; i < session.crawled_urls.size(); i++) {
      crawl_file << "  \"" << session.crawled_urls[i] << "\"";
      if (i < session.crawled_urls.size() - 1) crawl_file << ",";
      crawl_file << "\n";
    }
    crawl_file << "]\n";
    crawl_file.close();
  }

  // Save findings (append mode — each module adds its findings)
  std::ofstream findings_file(dir + "/findings.jsonl");
  if (findings_file.is_open()) {
    for (const auto& f : session.findings) {
      findings_file << "{\"type\":\"" << f.type << "\","
                    << "\"severity\":\"" << f.severity << "\","
                    << "\"url\":\"" << f.url << "\","
                    << "\"confidence\":" << f.confidence << ","
                    << "\"cwe\":\"" << f.cwe_id << "\"}\n";
    }
    findings_file.close();
  }

  // Save seeds
  if (!session.seeds.empty()) {
    std::ofstream seeds_file(dir + "/seeds.txt");
    for (const auto& s : session.seeds) seeds_file << s << "\n";
    seeds_file.close();
  }

  // Progress log
  std::ofstream log(dir + "/progress.log", std::ios::app);
  log << now_timestamp() << " | " << phase_name(session.phase) << " | modules: " << session.modules_completed << "/"
      << session.modules_total << " | findings: " << session.findings.size() << " | last: " << session.last_module << "\n";
  log.close();
}

ScanSession load_session(const std::string& target) {
  ScanSession session;
  session.target = target;

  std::string dir = session_dir(target);
  std::string state_path = dir + "/state.json";

  if (!fs::exists(state_path)) return session;

  // Parse state.json (simple line-by-line parsing)
  std::ifstream state(state_path);
  std::string line;
  while (std::getline(state, line)) {
    // Extract phase
    if (line.find("\"phase\"") != std::string::npos) {
      auto start = line.find(": \"") + 3;
      auto end = line.find("\"", start);
      if (start != std::string::npos && end != std::string::npos) {
        session.phase = parse_phase(line.substr(start, end - start));
      }
    }
    // Extract modules_completed
    if (line.find("\"modules_completed\"") != std::string::npos) {
      auto pos = line.find(": ") + 2;
      session.modules_completed = std::stoi(line.substr(pos));
    }
    // Extract modules_total
    if (line.find("\"modules_total\"") != std::string::npos) {
      auto pos = line.find(": ") + 2;
      session.modules_total = std::stoi(line.substr(pos));
    }
    // Extract session_id
    if (line.find("\"session_id\"") != std::string::npos) {
      auto start = line.find(": \"") + 3;
      auto end = line.find("\"", start);
      session.session_id = line.substr(start, end - start);
    }
    // Extract last_module
    if (line.find("\"last_module\"") != std::string::npos) {
      auto start = line.find(": \"") + 3;
      auto end = line.find("\"", start);
      session.last_module = line.substr(start, end - start);
    }
    // Check interrupted
    if (line.find("\"interrupted\": true") != std::string::npos) {
      session.interrupted = true;
    }
  }

  // Load crawled URLs
  std::string crawl_path = dir + "/crawl.json";
  if (fs::exists(crawl_path)) {
    std::ifstream crawl_file(crawl_path);
    std::string cline;
    while (std::getline(crawl_file, cline)) {
      auto start = cline.find("\"");
      if (start == std::string::npos) continue;
      start++;
      auto end = cline.find("\"", start);
      if (end != std::string::npos) {
        session.crawled_urls.push_back(cline.substr(start, end - start));
      }
    }
  }

  // Load seeds
  std::string seeds_path = dir + "/seeds.txt";
  if (fs::exists(seeds_path)) {
    std::ifstream seeds_file(seeds_path);
    std::string sline;
    while (std::getline(seeds_file, sline)) {
      if (!sline.empty()) session.seeds.push_back(sline);
    }
  }

  return session;
}

bool has_interrupted_session(const std::string& target) {
  std::string state_path = session_dir(target) + "/state.json";
  if (!fs::exists(state_path)) return false;

  // Check if it's actually interrupted (not completed)
  std::ifstream state(state_path);
  std::string content((std::istreambuf_iterator<char>(state)), std::istreambuf_iterator<char>());
  return content.find("\"interrupted\": true") != std::string::npos && content.find("\"phase\": \"completed\"") == std::string::npos;
}

void complete_session(const std::string& target) {
  std::string dir = session_dir(target);
  std::string state_path = dir + "/state.json";

  if (!fs::exists(state_path)) return;

  // Rewrite state with interrupted: false and phase: completed
  std::ofstream state(state_path);
  state << "{\n";
  state << "  \"target\": \"" << target << "\",\n";
  state << "  \"phase\": \"completed\",\n";
  state << "  \"interrupted\": false,\n";
  state << "  \"completed_at\": \"" << now_timestamp() << "\"\n";
  state << "}\n";
}

int completion_percent(const ScanSession& session) {
  // Weight each phase
  int phase_weight = static_cast<int>(session.phase) * 10;
  int module_weight = 0;
  if (session.modules_total > 0) {
    module_weight = (session.modules_completed * 40) / session.modules_total;
  }
  return std::min(100, phase_weight + module_weight);
}

}  // namespace apex
