#pragma once
#include "http.hpp"
#include <string>
#include <vector>

namespace apex {

struct OSINTLeak {
    std::string source;      // hibp, dehashed, pastebin
    std::string type;        // email, password, api_key, credential
    std::string value;       // leaked data
    std::string breach_name; // breach identifier
    std::string date;        // when leaked
    std::string severity;    // critical, high, medium
};

struct EmployeeExposure {
    std::string name;
    std::string email;
    std::string role;
    std::string linkedin_url;
    std::vector<std::string> skills;
    std::vector<std::string> breaches;
};

struct TechStackIntel {
    std::string source;      // job posting, dns, certificate
    std::string technology;
    std::string version;
    std::string url;
};

class OSINTScanner {
public:
    OSINTScanner(HttpClient& http);
    
    // Check emails against HaveIBeenPwned
    std::vector<OSINTLeak> check_hibp(const std::vector<std::string>& emails);
    
    // Scrape LinkedIn for employees (via Google dorking)
    std::vector<EmployeeExposure> find_employees(const std::string& domain);
    
    // Extract tech stack from job postings
    std::vector<TechStackIntel> scan_job_postings(const std::string& company);
    
    // Search for leaked credentials on Pastebin/GitHub
    std::vector<OSINTLeak> search_leaks(const std::string& domain);
    
    // Monitor news/legal mentions
    std::vector<std::string> monitor_news(const std::string& company);
    
    // DNS/Certificate intelligence
    std::vector<TechStackIntel> scan_infrastructure(const std::string& domain);
    
private:
    HttpClient& http_;
    std::string extract_emails(const std::string& content);
    std::vector<std::string> google_dork(const std::string& query);
};

} // namespace apex
