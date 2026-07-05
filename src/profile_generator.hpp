/// @file src/profile_generator.hpp
/// @brief Auto-learning ZAP profile generator interface.
#ifndef APEX_PROFILE_GENERATOR_HPP
#define APEX_PROFILE_GENERATOR_HPP

#include "crawler.hpp"
#include "scanner.hpp"
#include <chrono>
#include <set>
#include <string>
#include <vector>

namespace apex {

/// Intelligence gathered during a scan, used to generate profiles.
struct ScanIntel {
  std::string target;
  std::string scan_date;
  bool has_forms = false;
  bool has_api = false;
  bool has_auth = false;
  bool has_file_upload = false;
  bool has_ldap = false;
  bool is_spa = false;
  std::vector<std::string> interesting_paths;
};

/// Generates and updates ZAP scan profiles based on scan results.
/// Profiles are stored in profiles/<framework>/ and grow over time.
class ProfileGenerator {
public:
  explicit ProfileGenerator(const std::string &profiles_dir = "profiles");

  /// Check if a profile already exists for this framework.
  bool has_profile(const std::string &framework) const;

  /// Generate a new profile from scan intelligence.
  std::string generate_profile(const std::string &framework,
                               const ScanIntel &intel);

  /// Update existing profile with new paths/intel (learning).
  void update_profile(const std::string &framework, const ScanIntel &intel);

  /// Build ScanIntel from crawl results and findings.
  static ScanIntel build_intel(const std::string &target,
                               const CrawlResult &crawl,
                               const std::vector<Finding> &findings);

private:
  std::string profiles_dir_;
  std::set<std::string> known_profiles_;

  void load_known_profiles();
  static std::string normalize(const std::string &name);
};

} // namespace apex

#endif // APEX_PROFILE_GENERATOR_HPP
