#pragma once
#include "cms_detector.hpp"
#include "osint_export.hpp"
#include "scanner.hpp"
#include <map>
#include <string>
#include <vector>

namespace apex {

struct MaturityDimension {
  std::string name;
  int score; // 0-100
  std::string status;
};

struct MaturityScore {
  int level;      // 0-5
  int percentage; // 0-100
  std::map<std::string, MaturityDimension> dimensions;
  std::vector<std::string> recommendations;
  std::vector<std::string> next_level_requirements;
};

class MaturityCalculator {
public:
  MaturityScore calculate(const std::vector<Finding> &findings,
                          const std::vector<CMSVersion> &cms_versions,
                          const OSINTReport &osint);

private:
  int calculate_security_score(const std::vector<Finding> &findings);
  int calculate_maintainability_score(const std::vector<CMSVersion> &cms);
  int calculate_reliability_score(const OSINTReport &osint);

  std::vector<std::string>
  generate_recommendations(const std::vector<Finding> &findings,
                           const std::vector<CMSVersion> &cms,
                           const OSINTReport &osint);
};

} // namespace apex
