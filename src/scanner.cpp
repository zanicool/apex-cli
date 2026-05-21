/// @file scanner.cpp
/// @brief Scanner orchestrator: registers all feature modules, runs scanners
///        concurrently, deduplicates findings.
#include "scanner.hpp"
#include "scanners/scanner_base.hpp"
#include <algorithm>
#include <future>
#include <iostream>
#include <mutex>
#include <set>

namespace apex {

std::vector<Scanner> get_scanners() {
  std::vector<Scanner> all;
  auto append = [&](std::vector<Scanner> &&scanners) {
    all.insert(all.end(), std::make_move_iterator(scanners.begin()),
               std::make_move_iterator(scanners.end()));
  };

  append(register_core_scanners());
  append(register_smart_scanners());
  append(register_elite_scanners());
  append(register_godly_scanners());
  append(register_autonomous_scanners());
  append(register_browser_scanners());
  append(register_auth_scanners());
  append(register_injection_scanners());
  append(register_logic_scanners());
  append(register_modern_scanners());
  append(register_infrastructure_scanners());
  append(register_oob_scanners());
  append(register_recon_scanners());
  append(register_web_scanners());
  append(register_exploit_scanners());
  append(register_extra_scanners());
  append(register_waf_scanners());

  return all;
}

std::vector<Finding> run_scanners(const Config &cfg, HttpClient &http,
                                  const CrawlResult &crawl) {
  auto scanners = get_scanners();
  std::vector<Finding> all_findings;
  std::mutex mu;

  auto should_skip = [&](const std::string &name) {
    return std::any_of(cfg.skip.begin(), cfg.skip.end(),
                       [&](const std::string &s) { return s == name; });
  };

  std::vector<std::future<std::vector<Finding>>> futures;
  for (const auto &scanner : scanners) {
    if (should_skip(scanner.name)) {
      std::cout << "    [skip] " << scanner.name << "\n";
      continue;
    }
    std::cout << "    [->] " << scanner.name << "\n";
    futures.push_back(
        std::async(std::launch::async, scanner.func, std::cref(cfg),
                   std::ref(http), std::cref(crawl)));
  }

  for (auto &f : futures) {
    auto results = f.get();
    std::lock_guard<std::mutex> lock(mu);
    all_findings.insert(all_findings.end(), results.begin(), results.end());
  }

  // Deduplicate on type+url+param.
  std::set<std::string> seen;
  std::vector<Finding> deduped;
  for (auto &f : all_findings) {
    std::string key = f.type + "|" + f.url + "|" + f.param;
    if (seen.insert(key).second)
      deduped.push_back(std::move(f));
  }

  return deduped;
}

} // namespace apex
