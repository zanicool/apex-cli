/// @file origin_ip.hpp
/// @brief Find the real server IP behind WAF/CDN (Cloudflare, Akamai, etc).
/// Uses DNS history, certificate search, mail headers, and subdomain leaks.
#ifndef APEX_ORIGIN_IP_HPP
#define APEX_ORIGIN_IP_HPP

#include "http.hpp"
#include <set>
#include <string>
#include <vector>

namespace apex {

struct OriginResult {
  std::string ip;
  std::string source; // how we found it
  bool confirmed;     // responds with same content as target
};

/// Check if an IP belongs to a known CDN (not the origin).
inline bool is_cdn_ip(const std::string &ip);

/// Find origin IPs behind WAF for a given domain.
inline std::vector<OriginResult> find_origin_ip(HttpClient &http,
                                                 const std::string &domain) {
  std::vector<OriginResult> results;
  std::set<std::string> seen_ips;

  // 1. DNS History via SecurityTrails/ViewDNS
  {
    auto resp = http.get("https://viewdns.info/iphistory/?domain=" + domain);
    if (resp.status_code == 200) {
      // Extract IPs from the HTML table
      size_t pos = 0;
      while ((pos = resp.body.find("</td><td>", pos)) != std::string::npos) {
        pos += 9;
        // Look for IP pattern
        std::string chunk = resp.body.substr(pos, 20);
        std::string ip;
        for (char c : chunk) {
          if (c == '.' || (c >= '0' && c <= '9'))
            ip += c;
          else
            break;
        }
        // Validate IP format
        int dots = 0;
        for (char c : ip)
          if (c == '.') dots++;
        if (dots == 3 && ip.size() >= 7 && seen_ips.insert(ip).second) {
          results.push_back({ip, "DNS History (ViewDNS)", false});
        }
      }
    }
  }

  // 2. Certificate Transparency — find IPs that serve the same cert
  {
    auto resp = http.get("https://crt.sh/?q=" + domain + "&output=json");
    if (resp.status_code == 200 && resp.body.size() > 10) {
      // Extract unique common names / SANs that might reveal subdomains
      // pointing to origin
      size_t pos = 0;
      while ((pos = resp.body.find("\"common_name\":\"", pos)) !=
             std::string::npos) {
        pos += 15;
        auto end = resp.body.find("\"", pos);
        if (end != std::string::npos) {
          std::string cn = resp.body.substr(pos, end - pos);
          // Direct IP in cert
          int dots = 0;
          bool all_digits = true;
          for (char c : cn) {
            if (c == '.') dots++;
            else if (c < '0' || c > '9') all_digits = false;
          }
          if (dots == 3 && all_digits && seen_ips.insert(cn).second) {
            results.push_back({cn, "Certificate Transparency", false});
          }
        }
      }
    }
  }

  // 3. Subdomain IPs — mail, ftp, direct, cpanel often bypass WAF
  {
    std::vector<std::string> bypass_subs = {
        "mail", "ftp",    "direct", "origin", "old",    "dev",
        "cpanel", "webmail", "smtp",   "pop",    "imap",   "mx",
        "ns1",   "ns2",    "vpn",    "ssh",    "staging"};
    for (const auto &sub : bypass_subs) {
      std::string host = sub + "." + domain;
      // Resolve via DNS-over-HTTPS
      auto resp =
          http.get("https://dns.google/resolve?name=" + host + "&type=A");
      if (resp.status_code == 200) {
        size_t pos = 0;
        while ((pos = resp.body.find("\"data\":\"", pos)) != std::string::npos) {
          pos += 8;
          auto end = resp.body.find("\"", pos);
          if (end != std::string::npos) {
            std::string ip = resp.body.substr(pos, end - pos);
            int dots = 0;
            bool valid = true;
            for (char c : ip) {
              if (c == '.') dots++;
              else if (c < '0' || c > '9') valid = false;
            }
            if (dots == 3 && valid && seen_ips.insert(ip).second) {
              // Skip known CDN ranges
              if (!is_cdn_ip(ip)) {
                results.push_back({ip, "Subdomain: " + host, false});
              }
            }
          }
        }
      }
    }
  }

  // 4. Shodan/Censys — search for the SSL cert fingerprint
  {
    auto resp = http.get("https://www.shodan.io/search?query=ssl.cert.subject.cn:" + domain);
    if (resp.status_code == 200) {
      size_t pos = 0;
      while ((pos = resp.body.find("/host/", pos)) != std::string::npos) {
        pos += 6;
        auto end = resp.body.find("\"", pos);
        if (end != std::string::npos) {
          std::string ip = resp.body.substr(pos, end - pos);
          int dots = 0;
          bool valid = true;
          for (char c : ip) {
            if (c == '.') dots++;
            else if (c < '0' || c > '9') valid = false;
          }
          if (dots == 3 && valid && seen_ips.insert(ip).second) {
            if (!is_cdn_ip(ip)) {
              results.push_back({ip, "Shodan SSL cert match", false});
            }
          }
        }
      }
    }
  }

  // 5. Verify — check if found IPs serve the same site
  for (auto &r : results) {
    auto resp = http.get("http://" + r.ip,
                         {{"Host", domain}});
    if (resp.status_code == 200 && resp.body.size() > 500) {
      // Compare with a known element from the real site
      auto real = http.get("https://" + domain);
      if (real.status_code == 200) {
        // Check if title or key content matches
        auto get_title = [](const std::string &body) -> std::string {
          auto pos = body.find("<title>");
          if (pos == std::string::npos) return "";
          auto end = body.find("</title>", pos);
          if (end == std::string::npos) return "";
          return body.substr(pos + 7, end - pos - 7);
        };
        if (get_title(resp.body) == get_title(real.body) &&
            !get_title(resp.body).empty()) {
          r.confirmed = true;
        }
      }
    }
  }

  return results;
}

/// Check if an IP belongs to a known CDN (not the origin).
inline bool is_cdn_ip(const std::string &ip) {
  // Cloudflare ranges (simplified first octets)
  std::vector<std::string> cf_prefixes = {
      "104.16.", "104.17.", "104.18.", "104.19.", "104.20.",
      "104.21.", "104.22.", "104.23.", "104.24.", "104.25.",
      "172.64.", "172.65.", "172.66.", "172.67.",
      "173.245.", "103.21.", "103.22.", "103.31.",
      "141.101.", "108.162.", "190.93.", "188.114.",
      "197.234.", "198.41.", "162.158."};
  // Akamai
  std::vector<std::string> akamai_prefixes = {"23.32.", "23.33.", "23.64.",
                                               "23.65.", "104.64.", "104.65."};
  for (const auto &p : cf_prefixes)
    if (ip.substr(0, p.size()) == p) return true;
  for (const auto &p : akamai_prefixes)
    if (ip.substr(0, p.size()) == p) return true;
  return false;
}

} // namespace apex

#endif // APEX_ORIGIN_IP_HPP
