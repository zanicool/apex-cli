/// @file reporter.hpp
/// @brief Report generation: JSON and terminal output.
#ifndef APEX_REPORTER_HPP
#define APEX_REPORTER_HPP

#include "config.hpp"
#include "scanner.hpp"
#include <chrono>
#include <vector>

namespace apex {

/// Generate scan reports in configured formats.
void generate_report(const Config &cfg, const std::vector<Finding> &findings,
                     std::chrono::seconds elapsed);

} // namespace apex

#endif // APEX_REPORTER_HPP
