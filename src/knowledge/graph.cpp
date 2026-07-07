/// @file knowledge/graph.cpp
/// @brief Security Knowledge Graph implementation with built-in knowledge base.
#include "graph.hpp"
#include <algorithm>
#include <queue>

namespace apex {
namespace knowledge {

Graph::Graph() {}

void Graph::add_node(const Node &node) {
  nodes_[node.id] = node;
}

void Graph::add_edge(const Edge &edge) {
  edges_.push_back(edge);
}

std::vector<Edge> Graph::edges_from(const std::string &node_id) const {
  std::vector<Edge> result;
  for (const auto &e : edges_) {
    if (e.from_id == node_id) result.push_back(e);
  }
  return result;
}

std::vector<Edge> Graph::edges_to(const std::string &node_id) const {
  std::vector<Edge> result;
  for (const auto &e : edges_) {
    if (e.to_id == node_id) result.push_back(e);
  }
  return result;
}

std::vector<Node> Graph::nodes_of_type(NodeType type) const {
  std::vector<Node> result;
  for (const auto &[id, node] : nodes_) {
    if (node.type == type) result.push_back(node);
  }
  return result;
}

std::vector<std::string> Graph::traverse(const std::string &start,
                                          const std::set<EdgeType> &follow,
                                          int max_depth) const {
  std::vector<std::string> visited;
  std::queue<std::pair<std::string, int>> queue;
  std::set<std::string> seen;

  queue.push({start, 0});
  seen.insert(start);

  while (!queue.empty()) {
    auto [current, depth] = queue.front();
    queue.pop();
    if (depth > max_depth) continue;

    visited.push_back(current);

    for (const auto &edge : edges_from(current)) {
      if (follow.count(edge.type) && !seen.count(edge.to_id)) {
        seen.insert(edge.to_id);
        queue.push({edge.to_id, depth + 1});
      }
    }
  }

  return visited;
}

QueryResult Graph::risks_for(const std::string &technology) const {
  QueryResult result;
  auto reachable = traverse(technology, {EdgeType::HAS_RISK, EdgeType::COMMONLY_AFFECTED_BY}, 3);

  for (const auto &id : reachable) {
    auto it = nodes_.find(id);
    if (it != nodes_.end()) result.nodes.push_back(it->second);
  }

  for (const auto &e : edges_) {
    if (e.from_id == technology) result.edges.push_back(e);
  }

  result.confidence = result.nodes.empty() ? 0.0 : 0.7;
  return result;
}

QueryResult Graph::paths_to_impact(const std::string &from, const std::string &impact) const {
  QueryResult result;
  auto reachable = traverse(from, {EdgeType::LEADS_TO, EdgeType::CHAINS_WITH, EdgeType::HAS_RISK}, 5);

  bool found = false;
  for (const auto &id : reachable) {
    if (id == impact) { found = true; break; }
    auto it = nodes_.find(id);
    if (it != nodes_.end() && it->second.label == impact) { found = true; break; }
  }

  if (found) {
    for (const auto &id : reachable) {
      auto it = nodes_.find(id);
      if (it != nodes_.end()) result.nodes.push_back(it->second);
    }
    result.confidence = 0.6;
    result.explanation = "Path found from " + from + " to " + impact +
                         " via " + std::to_string(result.nodes.size()) + " intermediate nodes";
  }

  return result;
}

std::vector<std::string> Graph::suggest_next_tests(
    const std::set<std::string> &detected_technologies,
    const std::vector<std::string> &found_vuln_classes) const {

  std::set<std::string> suggestions;

  for (const auto &tech : detected_technologies) {
    auto risks = traverse(tech, {EdgeType::HAS_RISK, EdgeType::COMMONLY_AFFECTED_BY}, 2);
    for (const auto &risk : risks) {
      // If this risk hasn't been found yet, suggest testing it
      bool already_found = false;
      for (const auto &found : found_vuln_classes) {
        if (risk.find(found) != std::string::npos || found.find(risk) != std::string::npos) {
          already_found = true;
          break;
        }
      }
      if (!already_found) {
        auto it = nodes_.find(risk);
        if (it != nodes_.end() && it->second.type == NodeType::VULN_CLASS) {
          suggestions.insert(it->second.label);
        }
      }
    }
  }

  return std::vector<std::string>(suggestions.begin(), suggestions.end());
}

QueryResult Graph::predict_impact(
    const std::set<std::string> &technologies,
    const std::vector<std::string> &vuln_classes) const {

  QueryResult result;
  double max_confidence = 0.0;

  for (const auto &vuln : vuln_classes) {
    auto impacts = traverse(vuln, {EdgeType::LEADS_TO, EdgeType::CHAINS_WITH}, 3);
    for (const auto &imp : impacts) {
      auto it = nodes_.find(imp);
      if (it != nodes_.end() && it->second.type == NodeType::IMPACT) {
        result.nodes.push_back(it->second);
        // Boost confidence if technology matches
        for (const auto &tech : technologies) {
          for (const auto &edge : edges_from(tech)) {
            if (edge.to_id == vuln) max_confidence = std::max(max_confidence, edge.weight);
          }
        }
      }
    }
  }

  result.confidence = max_confidence;
  return result;
}

// ============================================================
// BUILT-IN SECURITY KNOWLEDGE BASE
// ============================================================

void Graph::load_default_knowledge() {
  // --- TECHNOLOGIES ---
  add_node({"nextjs", NodeType::TECHNOLOGY, "Next.js", {}});
  add_node({"react", NodeType::FRAMEWORK, "React", {}});
  add_node({"express", NodeType::TECHNOLOGY, "Express.js", {}});
  add_node({"nodejs", NodeType::TECHNOLOGY, "Node.js", {}});
  add_node({"django", NodeType::TECHNOLOGY, "Django", {}});
  add_node({"laravel", NodeType::TECHNOLOGY, "Laravel", {}});
  add_node({"rails", NodeType::TECHNOLOGY, "Ruby on Rails", {}});
  add_node({"spring", NodeType::TECHNOLOGY, "Spring Boot", {}});
  add_node({"wordpress", NodeType::TECHNOLOGY, "WordPress", {}});
  add_node({"graphql", NodeType::TECHNOLOGY, "GraphQL", {}});
  add_node({"jwt", NodeType::TECHNOLOGY, "JWT Authentication", {}});
  add_node({"oauth", NodeType::TECHNOLOGY, "OAuth 2.0", {}});

  // --- CLOUD ---
  add_node({"aws", NodeType::CLOUD_SERVICE, "Amazon Web Services", {}});
  add_node({"gcp", NodeType::CLOUD_SERVICE, "Google Cloud Platform", {}});
  add_node({"azure", NodeType::CLOUD_SERVICE, "Microsoft Azure", {}});
  add_node({"cloudflare", NodeType::CLOUD_SERVICE, "Cloudflare", {}});

  // --- VULNERABILITY CLASSES ---
  add_node({"pp", NodeType::VULN_CLASS, "Prototype Pollution", {}});
  add_node({"ssrf", NodeType::VULN_CLASS, "Server-Side Request Forgery", {}});
  add_node({"sqli", NodeType::VULN_CLASS, "SQL Injection", {}});
  add_node({"xss", NodeType::VULN_CLASS, "Cross-Site Scripting", {}});
  add_node({"ssti", NodeType::VULN_CLASS, "Template Injection", {}});
  add_node({"idor", NodeType::VULN_CLASS, "Insecure Direct Object Reference", {}});
  add_node({"jwt_weak", NodeType::VULN_CLASS, "JWT Weakness", {}});
  add_node({"oauth_misconfig", NodeType::VULN_CLASS, "OAuth Misconfiguration", {}});
  add_node({"race", NodeType::VULN_CLASS, "Race Condition", {}});
  add_node({"deserialization", NodeType::VULN_CLASS, "Insecure Deserialization", {}});
  add_node({"path_traversal", NodeType::VULN_CLASS, "Path Traversal", {}});
  add_node({"mass_assignment", NodeType::VULN_CLASS, "Mass Assignment", {}});
  add_node({"auth_bypass", NodeType::VULN_CLASS, "Authentication Bypass", {}});
  add_node({"cache_poison", NodeType::VULN_CLASS, "Cache Poisoning", {}});
  add_node({"smuggling", NodeType::VULN_CLASS, "Request Smuggling", {}});

  // --- IMPACTS ---
  add_node({"rce", NodeType::IMPACT, "Remote Code Execution", {}});
  add_node({"ato", NodeType::IMPACT, "Account Takeover", {}});
  add_node({"data_breach", NodeType::IMPACT, "Data Breach", {}});
  add_node({"priv_esc", NodeType::IMPACT, "Privilege Escalation", {}});
  add_node({"infra_compromise", NodeType::IMPACT, "Infrastructure Compromise", {}});
  add_node({"financial", NodeType::IMPACT, "Financial Loss", {}});
  add_node({"dos", NodeType::IMPACT, "Denial of Service", {}});

  // --- TECHNIQUES ---
  add_node({"alg_confusion", NodeType::TECHNIQUE, "Algorithm Confusion (RS256→HS256)", {}});
  add_node({"token_forgery", NodeType::TECHNIQUE, "Token Forgery", {}});
  add_node({"metadata_theft", NodeType::TECHNIQUE, "Cloud Metadata Theft", {}});
  add_node({"gadget_chain", NodeType::TECHNIQUE, "Gadget Chain Exploitation", {}});
  add_node({"single_packet", NodeType::TECHNIQUE, "Single Packet Race Attack", {}});

  // ============================================================
  // RELATIONSHIPS (the intelligence)
  // ============================================================

  // Next.js risks
  add_edge({"nextjs", "pp", EdgeType::HAS_RISK, 0.7, "Next.js apps use deep object merging"});
  add_edge({"nextjs", "ssrf", EdgeType::HAS_RISK, 0.5, "Server Actions can make server-side requests"});
  add_edge({"nextjs", "idor", EdgeType::HAS_RISK, 0.6, "API routes often lack authorization"});
  add_edge({"nextjs", "auth_bypass", EdgeType::HAS_RISK, 0.5, "Middleware bypass via path confusion"});

  // Express/Node.js risks
  add_edge({"express", "pp", EdgeType::HAS_RISK, 0.8, "Object merge in body-parser/lodash"});
  add_edge({"express", "deserialization", EdgeType::HAS_RISK, 0.4, "node-serialize if used"});
  add_edge({"nodejs", "pp", EdgeType::HAS_RISK, 0.9, "Prototype chain is fundamental to Node"});
  add_edge({"nodejs", "ssti", EdgeType::HAS_RISK, 0.5, "EJS/Pug template engines"});

  // Laravel risks
  add_edge({"laravel", "mass_assignment", EdgeType::HAS_RISK, 0.7, "Eloquent models"});
  add_edge({"laravel", "deserialization", EdgeType::HAS_RISK, 0.4, "Unserialize in cache/session"});
  add_edge({"laravel", "ssti", EdgeType::HAS_RISK, 0.3, "Blade templates mostly safe"});

  // Spring risks
  add_edge({"spring", "ssti", EdgeType::HAS_RISK, 0.6, "SpEL injection"});
  add_edge({"spring", "deserialization", EdgeType::HAS_RISK, 0.7, "Java deserialization gadgets"});
  add_edge({"spring", "ssrf", EdgeType::HAS_RISK, 0.5, "RestTemplate/WebClient"});

  // JWT risks
  add_edge({"jwt", "jwt_weak", EdgeType::HAS_RISK, 0.8, "Algorithm confusion, weak secrets"});
  add_edge({"jwt_weak", "alg_confusion", EdgeType::COMMONLY_AFFECTED_BY, 0.7, ""});
  add_edge({"jwt_weak", "token_forgery", EdgeType::LEADS_TO, 0.8, ""});
  add_edge({"token_forgery", "ato", EdgeType::LEADS_TO, 0.9, "Forged admin token = ATO"});
  add_edge({"token_forgery", "priv_esc", EdgeType::LEADS_TO, 0.9, ""});

  // OAuth risks
  add_edge({"oauth", "oauth_misconfig", EdgeType::HAS_RISK, 0.6, ""});
  add_edge({"oauth_misconfig", "ato", EdgeType::LEADS_TO, 0.8, "Token theft via redirect"});

  // SSRF chains
  add_edge({"ssrf", "metadata_theft", EdgeType::LEADS_TO, 0.7, "If in cloud environment"});
  add_edge({"metadata_theft", "infra_compromise", EdgeType::LEADS_TO, 0.9, "IAM creds = full access"});
  add_edge({"ssrf", "data_breach", EdgeType::LEADS_TO, 0.5, "Internal service access"});

  // Prototype Pollution chains
  add_edge({"pp", "gadget_chain", EdgeType::LEADS_TO, 0.6, "If gadget library present"});
  add_edge({"gadget_chain", "xss", EdgeType::LEADS_TO, 0.8, "innerHTML/srcdoc gadgets"});
  add_edge({"gadget_chain", "rce", EdgeType::LEADS_TO, 0.5, "Server-side: child_process gadget"});
  add_edge({"pp", "priv_esc", EdgeType::LEADS_TO, 0.6, "Pollute isAdmin property"});

  // SQL Injection chains
  add_edge({"sqli", "data_breach", EdgeType::LEADS_TO, 0.9, "Extract database contents"});
  add_edge({"sqli", "auth_bypass", EdgeType::LEADS_TO, 0.7, "Login bypass via tautology"});
  add_edge({"sqli", "rce", EdgeType::LEADS_TO, 0.3, "xp_cmdshell/INTO OUTFILE"});

  // Template Injection chains
  add_edge({"ssti", "rce", EdgeType::LEADS_TO, 0.9, "Direct code execution in template engine"});

  // Race condition chains
  add_edge({"race", "financial", EdgeType::LEADS_TO, 0.8, "Double-spend on payments"});
  add_edge({"race", "priv_esc", EdgeType::LEADS_TO, 0.5, "Duplicate account creation"});

  // Cache poisoning chains
  add_edge({"cache_poison", "xss", EdgeType::LEADS_TO, 0.7, "Stored XSS via cache"});
  add_edge({"cache_poison", "dos", EdgeType::LEADS_TO, 0.6, "Poison error page"});

  // Request smuggling chains
  add_edge({"smuggling", "ato", EdgeType::LEADS_TO, 0.7, "Steal next user's request"});
  add_edge({"smuggling", "cache_poison", EdgeType::CHAINS_WITH, 0.6, ""});

  // Cloud relationships
  add_edge({"aws", "ssrf", EdgeType::INCREASES_PROBABILITY, 0.8, "Metadata endpoint available"});
  add_edge({"gcp", "ssrf", EdgeType::INCREASES_PROBABILITY, 0.7, "Metadata endpoint available"});

  // GraphQL risks
  add_edge({"graphql", "idor", EdgeType::HAS_RISK, 0.7, "Node queries with IDs"});
  add_edge({"graphql", "data_breach", EdgeType::HAS_RISK, 0.5, "Introspection + batch queries"});
  add_edge({"graphql", "dos", EdgeType::HAS_RISK, 0.6, "Query depth abuse"});

  // WordPress risks
  add_edge({"wordpress", "sqli", EdgeType::HAS_RISK, 0.5, "Plugin vulnerabilities"});
  add_edge({"wordpress", "path_traversal", EdgeType::HAS_RISK, 0.4, "Theme/plugin file inclusion"});
  add_edge({"wordpress", "xss", EdgeType::HAS_RISK, 0.6, "Stored XSS in comments/posts"});
}

} // namespace knowledge
} // namespace apex
