#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include "http.hpp"

namespace apex {

enum class SeverityLevel {
    CRITICAL,
    HIGH,
    MEDIUM,
    LOW,
    INFO
};

struct SecurityFinding {
    std::string id;
    std::string name;
    std::string description;
    SeverityLevel severity;
    std::string url;
    std::string evidence;
    std::string cwe;
    std::string owasp_category;
};

class SecurityScanner {
public:
    explicit SecurityScanner(const std::string& target_url);
    
    // Core scanning
    std::vector<SecurityFinding> scan_full();
    std::vector<SecurityFinding> scan_fast();
    
    // Authentication
    void set_auth_jwt(const std::string& token);
    void set_auth_cookie(const std::string& name, const std::string& value);
    void set_auth_form(const std::string& login_url, const std::string& username, const std::string& password);
    
    // SPA/Next.js specific
    void enable_spa_mode(bool enable = true);
    void add_api_route(const std::string& route);
    void add_graphql_endpoint(const std::string& endpoint);
    
    // Reporting
    void export_json(const std::string& path) const;
    void export_html(const std::string& path) const;
    void export_jsonl(const std::string& path) const;
    
    // OWASP Top 10 coverage
    std::map<std::string, int> get_owasp_coverage() const;

private:
    std::string target_url_;
    std::unique_ptr<HttpClient> http_client_;
    std::vector<SecurityFinding> findings_;
    bool spa_mode_ = false;
    
    std::map<std::string, std::string> auth_headers_;
    std::vector<std::string> api_routes_;
    std::vector<std::string> graphql_endpoints_;
    
    // Vulnerability checks
    std::vector<SecurityFinding> check_injection();
    std::vector<SecurityFinding> check_xss();
    std::vector<SecurityFinding> check_auth();
    std::vector<SecurityFinding> check_access_control();
    std::vector<SecurityFinding> check_security_misconfig();
    std::vector<SecurityFinding> check_sensitive_data();
    std::vector<SecurityFinding> check_xxe();
    std::vector<SecurityFinding> check_deserialization();
    std::vector<SecurityFinding> check_components();
    std::vector<SecurityFinding> check_logging();
    std::vector<SecurityFinding> check_ssrf();
    
    // Next.js specific
    std::vector<SecurityFinding> check_nextjs_env_exposure();
    std::vector<SecurityFinding> check_nextjs_api_routes();
    std::vector<SecurityFinding> check_graphql_introspection();
    
    // Helpers
    bool is_vulnerable_to_sqli(const std::string& url, const std::string& param);
    bool is_vulnerable_to_xss(const std::string& url, const std::string& param);
    std::string generate_payload(const std::string& type);
};

} // namespace apex
