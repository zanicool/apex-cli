/// @file knowledge/graph.hpp
/// @brief Security Knowledge Graph — relationships between technologies,
///        vulnerabilities, attack techniques, and impact scenarios.
///
/// This is not a signature database. It's a reasoning substrate.
/// The graph encodes security knowledge as relationships that enable:
///   - "Next.js + Server Actions → check for authorization bypass"
///   - "JWT + HS256 → algorithm confusion likely → token forgery possible"
///   - "SSRF + AWS → metadata endpoint → IAM credential theft → critical"
///
/// The reasoning engine queries this graph to generate hypotheses
/// and predict impact without hardcoded if/else chains.
#ifndef APEX_KNOWLEDGE_GRAPH_HPP
#define APEX_KNOWLEDGE_GRAPH_HPP

#include <map>
#include <set>
#include <string>
#include <vector>

namespace apex {
namespace knowledge {

/// Node types in the knowledge graph.
enum class NodeType {
  TECHNOLOGY,       // "Next.js", "Express", "Django"
  FRAMEWORK,        // "React", "Vue", "Angular"
  VERSION,          // "14.x", "4.17.x"
  VULN_CLASS,       // "Prototype Pollution", "SSRF"
  CWE,             // "CWE-79", "CWE-918"
  TECHNIQUE,        // "single-packet race", "algorithm confusion"
  ENDPOINT_TYPE,    // "auth", "payment", "admin"
  EVIDENCE_TYPE,    // "timing differential", "error reflection"
  IMPACT,           // "RCE", "account takeover", "data breach"
  CONDITION,        // "requires auth", "needs JS enabled"
  CLOUD_SERVICE,    // "AWS", "GCP", "Azure"
};

/// Edge types (relationships).
enum class EdgeType {
  HAS_RISK,              // technology → vuln_class
  COMMONLY_AFFECTED_BY,  // technology → technique
  DETECTED_BY,           // vuln_class → evidence_type
  INCREASES_PROBABILITY, // condition → vuln_class
  LEADS_TO,              // vuln_class → impact
  REQUIRES_CONDITION,    // technique → condition
  MITIGATED_BY,          // vuln_class → technology (defense)
  CHAINS_WITH,           // vuln_class → vuln_class
  HOSTED_ON,             // technology → cloud_service
  VERSION_VULNERABLE,    // version → vuln_class
};

/// A node in the graph.
struct Node {
  std::string id;
  NodeType type;
  std::string label;
  std::map<std::string, std::string> properties; // Arbitrary metadata
};

/// An edge (relationship) in the graph.
struct Edge {
  std::string from_id;
  std::string to_id;
  EdgeType type;
  double weight = 1.0;    // Confidence/strength of relationship
  std::string description;
};

/// Query result from graph traversal.
struct QueryResult {
  std::vector<Node> nodes;
  std::vector<Edge> edges;
  double confidence = 0.0;
  std::string explanation;
};

/// The Knowledge Graph.
class Graph {
public:
  Graph();

  /// Load built-in security knowledge.
  void load_default_knowledge();

  /// Add a node.
  void add_node(const Node &node);

  /// Add a relationship.
  void add_edge(const Edge &edge);

  /// Query: what risks does this technology have?
  QueryResult risks_for(const std::string &technology) const;

  /// Query: what attack paths exist from A to impact B?
  QueryResult paths_to_impact(const std::string &from, const std::string &impact) const;

  /// Query: given these findings, what should we investigate next?
  std::vector<std::string> suggest_next_tests(
      const std::set<std::string> &detected_technologies,
      const std::vector<std::string> &found_vuln_classes) const;

  /// Query: what is the likely impact given these conditions?
  QueryResult predict_impact(
      const std::set<std::string> &technologies,
      const std::vector<std::string> &vuln_classes) const;

  /// Get all nodes of a type.
  std::vector<Node> nodes_of_type(NodeType type) const;

  /// Get all edges from a node.
  std::vector<Edge> edges_from(const std::string &node_id) const;

  /// Get all edges to a node.
  std::vector<Edge> edges_to(const std::string &node_id) const;

  /// Stats.
  size_t node_count() const { return nodes_.size(); }
  size_t edge_count() const { return edges_.size(); }

private:
  std::map<std::string, Node> nodes_;
  std::vector<Edge> edges_;

  // Traversal helper: BFS from node following edge types.
  std::vector<std::string> traverse(const std::string &start,
                                     const std::set<EdgeType> &follow,
                                     int max_depth = 5) const;
};

} // namespace knowledge
} // namespace apex

#endif // APEX_KNOWLEDGE_GRAPH_HPP
