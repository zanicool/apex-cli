#include "maturity.hpp"

#include <algorithm>
#include <numeric>

namespace apex {

int MaturityCalculator::calculate_security_score(const std::vector<Finding>& findings) {
  int critical = std::count_if(findings.begin(), findings.end(), [](const Finding& f) { return f.severity == "critical"; });
  int high = std::count_if(findings.begin(), findings.end(), [](const Finding& f) { return f.severity == "high"; });

  if (critical > 0) return 0;
  if (high > 5) return 40;
  if (high > 0) return 70;
  return 100;
}

int MaturityCalculator::calculate_maintainability_score(const std::vector<CMSVersion>& cms) {
  if (cms.empty()) return 100;

  int outdated = std::count_if(cms.begin(), cms.end(), [](const CMSVersion& c) { return c.outdated; });

  int uptodate_pct = ((cms.size() - outdated) * 100) / cms.size();
  return uptodate_pct;
}

int MaturityCalculator::calculate_reliability_score(const OSINTReport& osint) {
  int critical_leaks = std::count_if(osint.leaks.begin(), osint.leaks.end(), [](const OSINTLeak& l) { return l.severity == "critical"; });

  if (critical_leaks > 10) return 0;
  if (critical_leaks > 5) return 40;
  if (critical_leaks > 0) return 70;
  return 100;
}

std::vector<std::string> MaturityCalculator::generate_recommendations(const std::vector<Finding>& findings,
                                                                      const std::vector<CMSVersion>& cms, const OSINTReport& osint) {
  std::vector<std::string> recs;

  // Critical findings
  int critical = std::count_if(findings.begin(), findings.end(), [](const Finding& f) { return f.severity == "critical"; });
  if (critical > 0) {
    recs.push_back("Fix " + std::to_string(critical) + " critical vulnerabilities immediately");
  }

  // Outdated CMS
  for (const auto& c : cms) {
    if (c.outdated) {
      recs.push_back("Update " + c.name + " " + c.version + " → " + c.latest_version);
    }
  }

  // Critical leaks
  int critical_leaks = std::count_if(osint.leaks.begin(), osint.leaks.end(), [](const OSINTLeak& l) { return l.severity == "critical"; });
  if (critical_leaks > 0) {
    recs.push_back("Revoke " + std::to_string(critical_leaks) + " leaked credentials");
  }

  return recs;
}

MaturityScore MaturityCalculator::calculate(const std::vector<Finding>& findings, const std::vector<CMSVersion>& cms_versions,
                                            const OSINTReport& osint) {
  MaturityScore score;

  // Calculate dimension scores
  int security = calculate_security_score(findings);
  int maintainability = calculate_maintainability_score(cms_versions);
  int reliability = calculate_reliability_score(osint);

  score.dimensions["Security"] = {"Security", security, security >= 80 ? "Good" : security >= 60 ? "Fair" : "Poor"};
  score.dimensions["Maintainability"] = {"Maintainability", maintainability,
                                         maintainability >= 80   ? "Good"
                                         : maintainability >= 60 ? "Fair"
                                                                 : "Poor"};
  score.dimensions["Reliability"] = {"Reliability", reliability, reliability >= 80 ? "Good" : reliability >= 60 ? "Fair" : "Poor"};

  // Overall percentage (average of dimensions)
  score.percentage = (security + maintainability + reliability) / 3;

  // Map percentage to level (0-5)
  if (score.percentage >= 90)
    score.level = 5;
  else if (score.percentage >= 75)
    score.level = 4;
  else if (score.percentage >= 60)
    score.level = 3;
  else if (score.percentage >= 40)
    score.level = 2;
  else if (score.percentage >= 20)
    score.level = 1;
  else
    score.level = 0;

  // Generate recommendations
  score.recommendations = generate_recommendations(findings, cms_versions, osint);

  // Next level requirements
  if (score.level < 5) {
    int next_level = score.level + 1;
    int required_pct = next_level * 20;
    score.next_level_requirements.push_back("Achieve " + std::to_string(required_pct) + "% overall score");

    if (security < 80) {
      score.next_level_requirements.push_back("Improve security to 80%+");
    }
    if (maintainability < 80) {
      score.next_level_requirements.push_back("Update all CMS to latest versions");
    }
    if (reliability < 80) {
      score.next_level_requirements.push_back("Address all critical OSINT leaks");
    }
  }

  return score;
}

}  // namespace apex
