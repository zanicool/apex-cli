/// @file http.cpp
/// @brief HTTP client implementation using libcurl.
#include "http.hpp"
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <curl/curl.h>
#include <random>
#include <regex>
#include <thread>

namespace apex {

namespace {

/// User agents for rotation.
const char *kUserAgents[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) "
    "Gecko/20100101 Firefox/121.0",
};
constexpr size_t kNumAgents = sizeof(kUserAgents) / sizeof(kUserAgents[0]);

/// Callback for libcurl to write response body.
size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
  auto *buf = static_cast<std::string *>(userdata);
  size_t bytes = size * nmemb;
  buf->append(ptr, bytes);
  return bytes;
}

/// Callback for libcurl to capture response headers.
size_t header_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
  auto *headers = static_cast<std::map<std::string, std::string> *>(userdata);
  size_t bytes = size * nmemb;
  std::string line(ptr, bytes);
  auto colon = line.find(':');
  if (colon != std::string::npos) {
    std::string key = line.substr(0, colon);
    std::string val = line.substr(colon + 1);
    // Trim whitespace.
    val.erase(0, val.find_first_not_of(" \t"));
    val.erase(val.find_last_not_of("\r\n") + 1);
    (*headers)[key] = val;
  }
  return bytes;
}

} // namespace

HttpClient::HttpClient(const Config &cfg) : cfg_(cfg) {
  curl_global_init(CURL_GLOBAL_DEFAULT);
}

HttpClient::~HttpClient() {
  for (auto *h : pool_) {
    curl_easy_cleanup(static_cast<CURL *>(h));
  }
  curl_global_cleanup();
}

void *HttpClient::acquire_handle() {
  std::lock_guard<std::mutex> lock(pool_mu_);
  if (!pool_.empty()) {
    void *h = pool_.back();
    pool_.pop_back();
    return h;
  }
  return curl_easy_init();
}

void HttpClient::release_handle(void *handle) {
  std::lock_guard<std::mutex> lock(pool_mu_);
  pool_.push_back(handle);
}

Response HttpClient::get(const std::string &url) {
  return do_request("GET", url, "", {});
}

Response HttpClient::get_no_follow(const std::string &url) {
  return do_request("GET", url, "", {}, /*follow_redirects=*/false);
}

Response HttpClient::get(
    const std::string &url,
    const std::vector<std::pair<std::string, std::string>> &headers) {
  std::map<std::string, std::string> hmap(headers.begin(), headers.end());
  return do_request("GET", url, "", hmap);
}

Response HttpClient::post(const std::string &url, const std::string &body,
                          const std::string &content_type) {
  return do_request("POST", url, body, {{"Content-Type", content_type}});
}

Response HttpClient::post(
    const std::string &url, const std::string &body,
    const std::string &content_type,
    const std::vector<std::pair<std::string, std::string>> &headers) {
  std::map<std::string, std::string> hmap(headers.begin(), headers.end());
  hmap["Content-Type"] = content_type;
  return do_request("POST", url, body, hmap);
}

Response HttpClient::post_no_follow(const std::string &url,
                                    const std::string &body,
                                    const std::string &content_type) {
  std::map<std::string, std::string> hmap;
  hmap["Content-Type"] = content_type;
  return do_request("POST", url, body, hmap, /*follow_redirects=*/false);
}

long HttpClient::request_count() const { return req_count_.load(); }

Response HttpClient::do_request(
    const std::string &method, const std::string &url,
    const std::string &body,
    const std::map<std::string, std::string> &extra_headers,
    bool follow_redirects) {
  Response resp;
  resp.url = url;

  if (cfg_.dry_run) {
    return resp;
  }

  rate_limit();

  CURL *curl = static_cast<CURL *>(acquire_handle());
  if (!curl) {
    resp.error = "curl handle not available";
    return resp;
  }

  std::string resp_body;
  std::map<std::string, std::string> resp_headers;

  curl_easy_reset(curl);
  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp_body);
  curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
  curl_easy_setopt(curl, CURLOPT_HEADERDATA, &resp_headers);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, static_cast<long>(cfg_.timeout));
  curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, follow_redirects ? 1L : 0L);
  curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, random_ua().c_str());
  // Connection reuse and DNS cache.
  curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
  curl_easy_setopt(curl, CURLOPT_DNS_CACHE_TIMEOUT, 300L);

  if (!cfg_.proxy.empty()) {
    curl_easy_setopt(curl, CURLOPT_PROXY, cfg_.proxy.c_str());
  }

  if (method == "POST") {
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,
                     static_cast<long>(body.size()));
  }

  struct curl_slist *headers_list = nullptr;
  for (const auto &[key, val] : extra_headers) {
    std::string h = key + ": " + val;
    headers_list = curl_slist_append(headers_list, h.c_str());
  }
  if (headers_list) {
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers_list);
  }

  auto start = std::chrono::steady_clock::now();
  CURLcode res = curl_easy_perform(curl);
  auto end = std::chrono::steady_clock::now();

  resp.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      end - start);

  if (res != CURLE_OK) {
    resp.error = curl_easy_strerror(res);
  } else {
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    resp.status_code = static_cast<int>(code);
    resp.body = std::move(resp_body);
    resp.headers = std::move(resp_headers);
    resp.size = resp.body.size();
  }

  if (headers_list) {
    curl_slist_free_all(headers_list);
  }
  release_handle(curl);
  ++req_count_;
  return resp;
}

void HttpClient::rate_limit() {
  if (cfg_.rate <= 0.0) return;
  // Global token bucket: allow 1/rate requests per second.
  static std::mutex rate_mu;
  static auto last = std::chrono::steady_clock::now();
  std::lock_guard<std::mutex> lock(rate_mu);
  auto now = std::chrono::steady_clock::now();
  auto min_interval = std::chrono::milliseconds(
      static_cast<int>(cfg_.rate * 1000.0));
  auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
      now - last);
  if (elapsed < min_interval) {
    std::this_thread::sleep_for(min_interval - elapsed);
  }
  last = std::chrono::steady_clock::now();
}

std::string HttpClient::random_ua() const {
  static thread_local std::mt19937 rng(std::random_device{}());
  std::uniform_int_distribution<size_t> dist(0, kNumAgents - 1);
  return kUserAgents[dist(rng)];
}

std::string safe_name(const std::string &s) {
  std::string out = s;
  std::replace_if(
      out.begin(), out.end(), [](char c) { return !std::isalnum(c); }, '_');
  return out;
}

} // namespace apex
