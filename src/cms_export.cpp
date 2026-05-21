#include "cms_export.hpp"
#include <fstream>
#include <sstream>

namespace apex {

std::string export_cms_inventory(const std::vector<Finding>& findings) {
    std::ostringstream csv;
    csv << "URL,CMS,Version,Latest Version,Status,Severity\n";
    
    for (const auto& f : findings) {
        if (f.type != "CMS Detection") continue;
        
        // Parse evidence: "CMS|version|latest"
        std::string cms, version, latest;
        size_t pos1 = f.evidence.find('|');
        size_t pos2 = f.evidence.find('|', pos1 + 1);
        
        if (pos1 != std::string::npos && pos2 != std::string::npos) {
            cms = f.evidence.substr(0, pos1);
            version = f.evidence.substr(pos1 + 1, pos2 - pos1 - 1);
            latest = f.evidence.substr(pos2 + 1);
        }
        
        std::string status = (f.severity == "medium") ? "OUTDATED" : "OK";
        
        csv << f.url << ","
            << cms << ","
            << version << ","
            << latest << ","
            << status << ","
            << f.severity << "\n";
    }
    
    return csv.str();
}

void write_cms_inventory(const std::vector<Finding>& findings, const std::string& filename) {
    std::ofstream file(filename);
    if (file.is_open()) {
        file << export_cms_inventory(findings);
        file.close();
    }
}

} // namespace apex
