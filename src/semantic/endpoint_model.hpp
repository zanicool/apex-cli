/// @file semantic/endpoint_model.hpp
/// @brief Semantic Endpoint Model — understands what endpoints DO, not just what they ARE.
#ifndef APEX_SEMANTIC_ENDPOINT_HPP
#define APEX_SEMANTIC_ENDPOINT_HPP

#include <map>
#include <set>
#include <string>
#include <vector>

namespace apex {
namespace semantic {

/// What this endpoint does.
enum class Purpose {
  UNKNOWN,
  AUTH_LOGIN,         // User authentication
  AUTH_REGISTER,      // Account creation
  AUTH_RESET,         // Password reset
  AUTH_VERIFY,        // Email/2FA verification
  USER_PROFILE,       // View/edit user data
  USER_SETTINGS,      // Account settings
  PAYMENT_TRANSFER,   // Move money
  PAYMENT_CHECKOUT,   // Purchase flow
  PAYMENT_REFUND,     // Refund/chargeback
  ADMIN_MANAGE,       // Admin operations
  ADMIN_EXPORT,       // Data export
  DATA_READ,          // Read data
  DATA_WRITE,         // Write/update data
  DATA_DELETE,        // Delete data
  FILE_UPLOAD,        // File upload
  FILE_DOWNLOAD,      // File download
  SEARCH,            // Search/filter
  NOTIFICATION,      // Notifications/alerts
  WEBHOOK,           // External callback
  STATIC_CONTENT,    // Static page
  API_DISCOVERY,     // API docs/schema
};

/// Authentication requirement.
enum class AuthLevel {
  PUBLIC,            // No auth needed
  AUTHENTICATED,    // Any logged-in user
  PRIVILEGED,       // Special role required
  ADMIN,            // Admin only
  INTERNAL,         // Internal service only
};

/// The semantic profile of an endpoint.
struct EndpointProfile {
  std::string url;
  std::string method;            // GET, POST, PUT, DELETE
  Purpose purpose = Purpose::UNKNOWN;
  AuthLevel auth_level = AuthLevel::PUBLIC;
  int security_score = 0;        // 0-100 (how important to test)
  bool modifies_state = false;   // Does it change something?
  bool handles_money = false;    // Financial operation?
  bool handles_pii = false;      // Personal data?
  bool has_file_io = false;      // File operations?
  std::set<std::string> sensitive_params;  // Params worth testing
  std::string business_context;  // "payment", "auth", "admin", "user"
};

/// Classify an endpoint based on URL, method, params, and context.
EndpointProfile classify_endpoint(
    const std::string &url,
    const std::string &method,
    const std::set<std::string> &params,
    const std::set<std::string> &technologies);

/// Score endpoint security importance (0-100).
int score_endpoint(const EndpointProfile &profile);

/// Get testing priorities based on endpoint profiles.
/// Returns endpoints sorted by security importance.
std::vector<EndpointProfile> prioritize_endpoints(
    const std::vector<EndpointProfile> &profiles);

} // namespace semantic
} // namespace apex

#endif // APEX_SEMANTIC_ENDPOINT_HPP
