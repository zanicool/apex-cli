#include "osint_export.hpp"

#include <algorithm>
#include <fstream>
#include <set>
#include <sstream>

namespace apex {

void export_osint_report(const OSINTReport& report, const std::string& output_dir) {
  // 1. Leaks CSV
  std::ofstream leaks_file(output_dir + "/osint_leaks.csv");
  leaks_file << "Source,Type,Value,Breach,Date,Severity\n";
  for (const auto& leak : report.leaks) {
    leaks_file << leak.source << "," << leak.type << ","
               << "\"" << leak.value << "\"," << leak.breach_name << "," << leak.date << "," << leak.severity << "\n";
  }
  leaks_file.close();

  // 2. Employees CSV
  std::ofstream emp_file(output_dir + "/osint_employees.csv");
  emp_file << "Name,Email,Role,LinkedIn,Skills,Breaches\n";
  for (const auto& emp : report.employees) {
    std::string skills = "";
    for (const auto& s : emp.skills) skills += s + ";";

    std::string breaches = "";
    for (const auto& b : emp.breaches) breaches += b + ";";

    emp_file << "\"" << emp.name << "\"," << emp.email << "," << emp.role << "," << emp.linkedin_url << ","
             << "\"" << skills << "\","
             << "\"" << breaches << "\"\n";
  }
  emp_file.close();

  // 3. Tech Stack CSV
  std::ofstream tech_file(output_dir + "/osint_techstack.csv");
  tech_file << "Source,Technology,Version,URL\n";
  for (const auto& tech : report.tech_stack) {
    tech_file << tech.source << "," << tech.technology << "," << tech.version << "," << tech.url << "\n";
  }
  tech_file.close();

  // 4. News Mentions
  std::ofstream news_file(output_dir + "/osint_news.csv");
  news_file << "URL\n";
  for (const auto& url : report.news_mentions) {
    news_file << url << "\n";
  }
  news_file.close();
}

std::string generate_osint_summary(const OSINTReport& report) {
  std::ostringstream summary;

  summary << "\n=== OSINT INTELLIGENCE SUMMARY ===\n\n";

  // Critical findings
  int critical_leaks = std::count_if(report.leaks.begin(), report.leaks.end(), [](const OSINTLeak& l) { return l.severity == "critical"; });

  summary << "🔴 CRITICAL FINDINGS:\n";
  summary << "  - " << critical_leaks << " critical leaks detected\n";
  summary << "  - " << report.employees.size() << " employees exposed\n\n";

  // Breach summary
  summary << "📊 DATA BREACHES:\n";
  std::map<std::string, int> breach_counts;
  for (const auto& leak : report.leaks) {
    if (!leak.breach_name.empty()) {
      breach_counts[leak.breach_name]++;
    }
  }
  for (const auto& [breach, count] : breach_counts) {
    summary << "  - " << breach << ": " << count << " accounts\n";
  }
  summary << "\n";

  // Tech stack
  summary << "💻 TECHNOLOGY STACK:\n";
  std::set<std::string> unique_tech;
  for (const auto& tech : report.tech_stack) {
    unique_tech.insert(tech.technology);
  }
  for (const auto& tech : unique_tech) {
    summary << "  - " << tech << "\n";
  }
  summary << "\n";

  // Recommendations
  summary << "⚠️  IMMEDIATE ACTIONS:\n";
  if (critical_leaks > 0) {
    summary << "  1. Force password reset for all breached accounts\n";
    summary << "  2. Enable 2FA/MFA immediately\n";
    summary << "  3. Rotate all API keys and secrets\n";
  }
  if (!report.employees.empty()) {
    summary << "  4. Security awareness training for exposed employees\n";
    summary << "  5. Review LinkedIn profiles for sensitive info\n";
  }
  summary << "  6. Monitor dark web for company mentions\n";
  summary << "  7. Implement continuous OSINT monitoring\n\n";

  summary << "📁 Detailed reports exported to:\n";
  summary << "  - osint_leaks.csv\n";
  summary << "  - osint_employees.csv\n";
  summary << "  - osint_techstack.csv\n";
  summary << "  - osint_news.csv\n";

  return summary.str();
}

}  // namespace apex
