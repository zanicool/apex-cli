/// @file payloads.hpp
/// @brief Load payload files from Zani's original collections.
#ifndef APEX_PAYLOADS_HPP
#define APEX_PAYLOADS_HPP

#include <string>
#include <vector>

namespace apex {

/// Load lines from a payload/wordlist file. Returns hardcoded fallback if file not found.
std::vector<std::string> load_payloads(const std::string &filename);

} // namespace apex

#endif // APEX_PAYLOADS_HPP
