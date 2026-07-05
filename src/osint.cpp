#include "osint.hpp"
#include <regex>
#include <set>

namespace apex {

OSINTScanner::OSINTScanner(HttpClient &http) : http_(http) {}

std::vector<OSINTLeak>
OSINTScanner::check_hibp(const std::vector<std::string> &emails) {
  std::vector<OSINTLeak> leaks;
  for (const auto &email : emails) {
    std::string url =
        "https://haveibeenpwned.com/api/v3/breachedaccount/" + email;
    auto resp = http_.get(url);
    if (resp.status_code == 200) {
      std::regex breach_re("\"Name\":\"([^\"]+)\"");
      std::smatch m;
      std::string body = resp.body;
      while (std::regex_search(body, m, breach_re)) {
        leaks.push_back(
            {"HaveIBeenPwned", "email", email, m[1].str(), "", "high"});
        body = m.suffix();
      }
    }
  }
  return leaks;
}

std::vector<std::string> OSINTScanner::google_dork(const std::string &query) {
  std::vector<std::string> results;
  std::string url = "https://www.google.com/search?q=" + query;
  auto resp = http_.get(url);
  std::regex url_re("https?://[^\\s\"<>]+");
  std::smatch m;
  std::string body = resp.body;
  while (std::regex_search(body, m, url_re)) {
    results.push_back(m[0].str());
    body = m.suffix();
    if (results.size() >= 50)
      break;
  }
  return results;
}

std::vector<EmployeeExposure>
OSINTScanner::find_employees(const std::string &domain) {
  std::vector<EmployeeExposure> employees;
  std::string query = "site:linkedin.com/in/ \"@" + domain + "\"";
  auto urls = google_dork(query);
  std::regex email_re("[a-zA-Z0-9._%+-]+@" + domain);
  for (const auto &url : urls) {
    if (url.find("linkedin.com/in/") != std::string::npos) {
      auto resp = http_.get(url);
      std::regex name_re("<title>([^|]+)");
      std::smatch m;
      if (std::regex_search(resp.body, m, name_re)) {
        EmployeeExposure emp;
        emp.name = m[1].str();
        emp.linkedin_url = url;
        if (std::regex_search(resp.body, m, email_re)) {
          emp.email = m[0].str();
        }
        employees.push_back(emp);
      }
    }
  }
  return employees;
}

std::vector<TechStackIntel>
OSINTScanner::scan_job_postings(const std::string &company) {
  std::vector<TechStackIntel> stack;
  std::vector<std::string> sources = {"site:linkedin.com/jobs \"" + company +
                                          "\"",
                                      "site:indeed.com \"" + company + "\""};
  std::vector<std::string> tech_keywords = {
      "AWS", "Azure", "Kubernetes", "Docker", "React", "Python", "PostgreSQL"};
  for (const auto &query : sources) {
    auto urls = google_dork(query);
    for (const auto &url : urls) {
      auto resp = http_.get(url);
      for (const auto &tech : tech_keywords) {
        if (resp.body.find(tech) != std::string::npos) {
          stack.push_back({"job_posting", tech, "", url});
        }
      }
    }
  }
  return stack;
}

std::vector<OSINTLeak> OSINTScanner::search_leaks(const std::string &domain) {
  std::vector<OSINTLeak> leaks;
  std::string github_query = "site:github.com \"" + domain + "\" password";
  auto github_urls = google_dork(github_query);
  for (const auto &url : github_urls) {
    leaks.push_back({"GitHub", "potential_leak", url, "", "", "critical"});
  }
  return leaks;
}

std::vector<std::string>
OSINTScanner::monitor_news(const std::string &company) {
  std::vector<std::string> mentions;
  std::vector<std::string> queries = {company + " breach",
                                      company + " lawsuit"};
  for (const auto &query : queries) {
    auto urls = google_dork(query);
    mentions.insert(mentions.end(), urls.begin(), urls.end());
  }
  return mentions;
}

std::vector<TechStackIntel>
OSINTScanner::scan_infrastructure(const std::string &domain) {
  std::vector<TechStackIntel> intel;
  std::string ct_query = "https://crt.sh/?q=%." + domain + "&output=json";
  auto ct_resp = http_.get(ct_query);
  std::regex subdomain_re("\"name_value\":\"([^\"]+)\"");
  std::smatch m;
  std::string body = ct_resp.body;
  std::set<std::string> subdomains;
  while (std::regex_search(body, m, subdomain_re)) {
    subdomains.insert(m[1].str());
    body = m.suffix();
  }
  for (const auto &subdomain : subdomains) {
    intel.push_back({"Certificate", "subdomain", subdomain, "crt.sh"});
  }
  return intel;
}

} // namespace apex
