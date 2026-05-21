/// @file payloads.cpp
/// @brief Runtime payload loader — uses Zani's original payload collections.
#include "payloads.hpp"
#include <filesystem>
#include <fstream>

namespace apex {

namespace {

/// Search paths for payload files.
std::string find_payload_file(const std::string &filename) {
  std::vector<std::string> search = {
      filename,
      "payloads/" + filename,
      "wordlists/" + filename,
      "../payloads/" + filename,
      "../wordlists/" + filename,
  };
  for (const auto &p : search) {
    if (std::filesystem::exists(p)) return p;
  }
  return "";
}

} // namespace

std::vector<std::string> load_payloads(const std::string &filename) {
  std::vector<std::string> lines;
  std::string path = find_payload_file(filename);
  if (path.empty()) return lines;

  std::ifstream file(path);
  std::string line;
  while (std::getline(file, line)) {
    if (!line.empty() && line[0] != '#') {
      lines.push_back(line);
    }
  }
  return lines;
}

} // namespace apex
