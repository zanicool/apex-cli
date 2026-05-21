#pragma once
#include "osint.hpp"
#include <string>

namespace apex {

/// Generate comprehensive OSINT report in CSV format
struct OSINTReport {
    std::vector<OSINTLeak> leaks;
    std::vector<EmployeeExposure> employees;
    std::vector<TechStackIntel> tech_stack;
    std::vector<std::string> news_mentions;
};

/// Export to multiple CSV files for easy analysis
void export_osint_report(const OSINTReport& report, const std::string& output_dir);

/// Generate summary dashboard
std::string generate_osint_summary(const OSINTReport& report);

} // namespace apex
