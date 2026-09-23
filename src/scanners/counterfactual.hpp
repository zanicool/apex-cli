/// @file scanners/counterfactual.hpp
/// @brief Pure proof predicates for counterfactual injection consensus.
#ifndef APEX_COUNTERFACTUAL_HPP
#define APEX_COUNTERFACTUAL_HPP

#include "../http.hpp"

#include <cctype>
#include <string>

namespace apex {

inline bool contains_standalone_token(const std::string &body,
                                      const std::string &token) {
  if (token.empty()) return false;
  size_t pos = body.find(token);
  while (pos != std::string::npos) {
    const bool left_ok =
        pos == 0 || !std::isdigit(static_cast<unsigned char>(body[pos - 1]));
    const size_t end = pos + token.size();
    const bool right_ok =
        end == body.size() ||
        !std::isdigit(static_cast<unsigned char>(body[end]));
    if (left_ok && right_ok) return true;
    pos = body.find(token, pos + 1);
  }
  return false;
}

/// Require two independent evaluated canaries plus a syntax-matched negative
/// control. This rejects reflection, static-number collisions, WAF blocks, and
/// one-off dynamic response changes.
inline bool confirms_counterfactual_template_consensus(
    const Response &baseline, const Response &positive_a,
    const Response &positive_b, const Response &negative_control,
    const std::string &expected_a, const std::string &expected_b) {
  auto success = [](const Response &response) {
    return response.status_code >= 200 && response.status_code < 400;
  };
  if (!success(baseline) || !success(positive_a) || !success(positive_b) ||
      negative_control.status_code == 0) {
    return false;
  }

  return contains_standalone_token(positive_a.body, expected_a) &&
         contains_standalone_token(positive_b.body, expected_b) &&
         !contains_standalone_token(baseline.body, expected_a) &&
         !contains_standalone_token(baseline.body, expected_b) &&
         !contains_standalone_token(negative_control.body, expected_a) &&
         !contains_standalone_token(negative_control.body, expected_b);
}

} // namespace apex

#endif // APEX_COUNTERFACTUAL_HPP
