/// @file pipeline.hpp
/// @brief Full bug bounty pipeline: recon → smart scan → deep → novelty →
/// report.
///
/// Based on PTES methodology + honeypot research insights:
/// - Attackers check /.git, /env, metadata FIRST (we do too)
/// - Sequential: broad recon → targeted deep scan → verify → report
/// - Honeypot data shows: unique endpoints > common endpoints
/// - Focus on what others DON'T find (lateral thinking)
#ifndef APEX_PIPELINE_HPP
#define APEX_PIPELINE_HPP

#include "confidence.hpp"
#include "crawler.hpp"
#include "http.hpp"
#include "novelty.hpp"
#include "owasp_intel.hpp"
#include "scanner.hpp"
#include "smart_mode.hpp"
#include <chrono>
#include <iostream>
#include <string>
#include <vector>

namespace apex {

/// Pipeline stage result.
struct PipelineStage {
  std::string name;
  int findings_count = 0;
  double seconds = 0;
};

/// Full pipeline result.
struct PipelineResult {
  std::vector<PipelineStage> stages;
  std::vector<Finding> reportable;   // Worth submitting
  std::vector<Finding> verify_first; // Check hacktivity
  std::vector<Finding> skip;         // Likely dupes
  int total_findings = 0;
  double total_seconds = 0;
};

/// Print the pipeline banner.
inline void print_pipeline_banner(const std::string &target) {
  std::cout << R"(
╔══════════════════════════════════════════════════════════════╗
║  APEX BOUNTY PIPELINE                                        ║
║  Target: )"
            << target.substr(0, 50) << R"(
╚══════════════════════════════════════════════════════════════╝
)" << "\n";
}

/// Print stage header.
inline void print_stage(int num, int total, const std::string &name,
                        const std::string &desc) {
  std::cout << "\n[" << num << "/" << total << "] " << name << " — " << desc
            << "\n";
}

/// Print the final pipeline report.
inline void print_pipeline_report(const PipelineResult &result) {
  std::cout << R"(
╔══════════════════════════════════════════════════════════════╗
║  PIPELINE COMPLETE                                           ║
╚══════════════════════════════════════════════════════════════╝
)";

  // Stage summary
  std::cout << "\n  Stages:\n";
  for (const auto &s : result.stages) {
    printf("    %-20s %3d findings  %5.1fs\n", s.name.c_str(), s.findings_count,
           s.seconds);
  }
  std::cout << "    ────────────────────────────────────────\n";
  printf("    %-20s %3d findings  %5.1fs\n", "TOTAL", result.total_findings,
         result.total_seconds);

  // Reportable findings
  if (!result.reportable.empty()) {
    std::cout << "\n  🟢 SUBMIT THESE (" << result.reportable.size()
              << "):\n\n";
    for (const auto &f : result.reportable) {
      print_enriched_finding(f);
    }
  }

  // Verify first
  if (!result.verify_first.empty()) {
    std::cout << "  🟡 VERIFY FIRST (" << result.verify_first.size()
              << ") — check hacktivity before submitting:\n\n";
    for (size_t i = 0; i < result.verify_first.size() && i < 10; ++i) {
      const auto &f = result.verify_first[i];
      std::cout << "    [" << f.severity << "] " << f.type << " — " << f.url
                << "\n";
    }
    if (result.verify_first.size() > 10)
      std::cout << "    ... and " << (result.verify_first.size() - 10)
                << " more\n";
    std::cout << "\n";
  }

  // Skip
  if (!result.skip.empty()) {
    std::cout << "  🔴 SKIP (" << result.skip.size()
              << ") — likely duplicates:\n";
    for (size_t i = 0; i < result.skip.size() && i < 5; ++i) {
      std::cout << "    " << result.skip[i].type << " — " << result.skip[i].url
                << "\n";
    }
    if (result.skip.size() > 5)
      std::cout << "    ... and " << (result.skip.size() - 5) << " more\n";
    std::cout << "\n";
  }

  // Tips based on findings
  std::cout << "  💡 TIPS:\n";
  if (result.reportable.empty() && result.verify_first.empty()) {
    std::cout << "    • No high-novelty findings. Try:\n";
    std::cout << "      - Authenticated scanning (--cookie / --auth-header)\n";
    std::cout
        << "      - Different endpoints (check JS files for hidden APIs)\n";
    std::cout << "      - Business logic flaws (manual testing)\n";
    std::cout << "      - Race conditions, 2FA bypass, password reset flows\n";
  } else {
    std::cout << "    • Write clear PoC with reproduction steps\n";
    std::cout << "    • Show business impact (not just technical)\n";
    std::cout << "    • Check program policy for bonus criteria\n";
    std::cout
        << "    • One report per vulnerability (don't chain unless needed)\n";
  }
  std::cout << "\n";
}

} // namespace apex

#endif // APEX_PIPELINE_HPP
