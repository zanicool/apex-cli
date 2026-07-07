/// @file http.hpp
/// @brief HTTP client with TLS rotation, rate limiting, and concurrency.
#ifndef APEX_HTTP_HPP
#define APEX_HTTP_HPP

#include "config.hpp"
#include <atomic>
#include <chrono>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace apex {

/// HTTP response data.
struct Response {
  std::string url;
  int status_code = 0;
  std::string body;
  std::map<std::string, std::string> headers;
  size_t size = 0;
  std::chrono::milliseconds duration{0};
  std::string error;
};

/// HTTP client with connection pooling and UA rotation.
class HttpClient {
public:
  explicit HttpClient(const Config &cfg);
  ~HttpClient();

  /// Perform a GET request.
  Response get(const std::string &url);

  /// GET with custom headers.
  Response get(const std::string &url,
               const std::vector<std::pair<std::string, std::string>> &headers);

  /// Perform a POST request.
  Response post(const std::string &url, const std::string &body,
                const std::string &content_type);

  /// POST with custom headers.
  Response
  post(const std::string &url, const std::string &body,
       const std::string &content_type,
       const std::vector<std::pair<std::string, std::string>> &headers);

  /// Total requests made.
  long request_count() const;

private:
  Response do_request(const std::string &method, const std::string &url,
                      const std::string &body,
                      const std::map<std::string, std::string> &headers);
  void rate_limit();
  std::string random_ua() const;
  void *acquire_handle();
  void release_handle(void *handle);

  const Config &cfg_;
  std::atomic<long> req_count_{0};
  std::mutex pool_mu_;
  std::vector<void *> pool_;

  // Request-level intelligent cache
  // Key: method + url + sorted_headers_hash
  // Shares responses across scanner modules (same URL = 1 request)
  std::mutex cache_mu_;
  std::map<std::string, Response> response_cache_;
  std::atomic<long> cache_hits_{0};

  std::string cache_key(const std::string &method, const std::string &url,
                         const std::map<std::string, std::string> &headers) const;
  Response *cache_lookup(const std::string &key);
  void cache_store(const std::string &key, const Response &resp);
};

/// Sanitize a string for use in filenames.
std::string safe_name(const std::string &s);

} // namespace apex

#endif // APEX_HTTP_HPP
