/// @file checkpoint.hpp
/// @brief Scan Checkpoint Engine — save/restore scan state for crash recovery.
///
/// A scan can be interrupted at any point and resumed without losing progress.
/// State is persisted to disk after each phase and each scanner module.
///
/// States: INIT → RECON → CRAWL → PROFILE → SCANNING → VERIFY → REASON → COMPLETE
#ifndef APEX_CHECKPOINT_HPP
#define APEX_CHECKPOINT_HPP

#include "config.hpp"
#include "crawler.hpp"
#include "scanner.hpp"
#include <string>
#include <vector>

namespace apex {

/// Scan phases (ordered).
enum class ScanPhase {
  INIT = 0,
  RECON_COMPLETE = 1,
  CRAWL_COMPLETE = 2,
  PROFILE_COMPLETE = 3,
  SCANNING = 4,         // In progress — check modules_completed
  SCAN_COMPLETE = 5,
  VERIFICATION = 6,
  REASONING = 7,
  REPORT = 8,
  COMPLETED = 9
};

/// Persistent scan session state.
struct ScanSession {
  std::string target;
  std::string session_id;       // Unique ID for this scan
  std::string start_time;
  ScanPhase phase = ScanPhase::INIT;
  int modules_completed = 0;    // How many scanner modules finished
  int modules_total = 0;
  std::vector<std::string> seeds;           // Recon results
  std::vector<std::string> crawled_urls;    // Crawl results
  std::vector<std::string> technologies;    // Detected tech
  std::vector<Finding> findings;            // Accumulated findings
  int total_requests = 0;
  std::string last_module;      // Last completed module name
  bool interrupted = false;
};

/// Get the session directory for a target.
std::string session_dir(const std::string &target);

/// Save current scan state to disk.
void save_checkpoint(const ScanSession &session);

/// Load a previous interrupted session (if any).
/// Returns empty session if no interrupted scan found.
ScanSession load_session(const std::string &target);

/// Check if an interrupted session exists for this target.
bool has_interrupted_session(const std::string &target);

/// Mark session as complete (cleanup).
void complete_session(const std::string &target);

/// Get completion percentage.
int completion_percent(const ScanSession &session);

} // namespace apex

#endif // APEX_CHECKPOINT_HPP
