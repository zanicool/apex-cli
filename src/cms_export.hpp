#pragma once
#include "scanner.hpp"
#include <string>
#include <vector>

namespace apex {

/// Export CMS findings to CSV format for inventory management.
std::string export_cms_inventory(const std::vector<Finding>& findings);

/// Write CSV inventory to file.
void write_cms_inventory(const std::vector<Finding>& findings, const std::string& filename);

} // namespace apex
