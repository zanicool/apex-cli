/// @file scanners/scanner_base.hpp
/// @brief Shared types and helpers for scanner feature modules.
#ifndef APEX_SCANNERS_BASE_HPP
#define APEX_SCANNERS_BASE_HPP

#include "../config.hpp"
#include "../crawler.hpp"
#include "../http.hpp"
#include "../scanner.hpp"
#include <algorithm>
#include <regex>
#include <string>
#include <vector>

namespace apex {

/// Helper: extract base URL from a full URL.
inline std::string base_url_from(const std::string &url) {
  size_t pos = url.find("://");
  if (pos != std::string::npos) {
    pos = url.find("/", pos + 3);
    if (pos != std::string::npos) return url.substr(0, pos);
  }
  return url;
}

/// Helper: get parameter injection targets for a URL.
inline std::vector<std::pair<std::string, std::string>>
get_targets(const CrawlResult &crawl, const std::string &url,
            const std::string &default_param = "id") {
  std::vector<std::pair<std::string, std::string>> targets;
  // Strip query string for comparison (crawl.params stores base URL only)
  std::string base_url = url;
  auto qpos = base_url.find('?');
  if (qpos != std::string::npos) base_url = base_url.substr(0, qpos);
  for (const auto &p : crawl.params) {
    if (p.url == base_url) targets.push_back({p.url + "?" + p.name + "=", p.name});
  }
  if (targets.empty())
    targets.push_back({base_url + "?" + default_param + "=", default_param});
  return targets;
}

/// Helper: check if string contains any of the given substrings.
inline bool contains_any(const std::string &s,
                         const std::vector<std::string> &substrs) {
  return std::any_of(substrs.begin(), substrs.end(),
                     [&](const std::string &sub) {
                       return s.find(sub) != std::string::npos;
                     });
}

/// Baseline helpers for FP reduction.
inline bool has_indicator_in_resp(const std::string &body, const std::string &indicator) {
  return body.find(indicator) != std::string::npos;
}

/// Check if an indicator appears ONLY in the payload response and not in baseline.
/// This is the core FP filter: a real vulnerability manifests as indicator present
/// after payload injection but absent from normal (baseline) response.
inline bool has_baseline_diff_indicator(const std::string &payload_resp_body,
                                       const std::string &baseline_body,
                                       const std::string &indicator) {
  if (indicator.empty()) return false;
  bool in_payload = payload_resp_body.find(indicator) != std::string::npos;
  bool in_baseline = baseline_body.find(indicator) != std::string::npos;
  return in_payload && !in_baseline;
}

/// Check multiple indicators — all must be absent from baseline if present in payload.
inline bool has_baseline_diff_any(const std::string &payload_resp_body,
                                  const std::string &baseline_body,
                                  const std::vector<std::string> &indicators) {
  for (const auto &ind : indicators) {
    if (has_baseline_diff_indicator(payload_resp_body, baseline_body, ind))
      return true;
  }
  return false;
}

/// Size-based diff: payload body significantly larger than baseline.
/// Returns true only when the delta exceeds threshold AND both have content.
inline bool has_size_diff(const std::string &payload_resp_body,
                          const std::string &baseline_body,
                          size_t min_delta = 50) {
  if (baseline_body.empty() || payload_resp_body.size() <= baseline_body.size())
    return false;
  auto delta = payload_resp_body.size() - baseline_body.size();
  return delta > min_delta;
}

/// Timing-based anomaly: requires baseline average and confirms significant deviation.
inline bool has_timing_anomaly(std::chrono::milliseconds payload_duration,
                               const std::vector<std::chrono::milliseconds> &baseline_samples) {
  if (baseline_samples.empty() || baseline_samples.size() < 2) return false;
  // Compute mean of baseline samples
  int64_t sum = 0;
  for (auto s : baseline_samples) sum += static_cast<int64_t>(s.count());
  double avg_ms = static_cast<double>(sum) / baseline_samples.size();
  if (avg_ms < 1.0) return false; // Baseline too fast to be meaningful
  return payload_duration.count() > 2.0 * avg_ms;
}

/// Registration functions — each module provides one.
std::vector<Scanner> register_core_scanners();
std::vector<Scanner> register_smart_scanners();
std::vector<Scanner> register_elite_scanners();
std::vector<Scanner> register_godly_scanners();
std::vector<Scanner> register_autonomous_scanners();
std::vector<Scanner> register_browser_scanners();
std::vector<Scanner> register_auth_scanners();
std::vector<Scanner> register_injection_scanners();
std::vector<Scanner> register_logic_scanners();
std::vector<Scanner> register_modern_scanners();
std::vector<Scanner> register_infrastructure_scanners();
std::vector<Scanner> register_oob_scanners();
std::vector<Scanner> register_recon_scanners();
std::vector<Scanner> register_web_scanners();
std::vector<Scanner> register_exploit_scanners();
std::vector<Scanner> register_extra_scanners();
std::vector<Scanner> register_waf_scanners();
std::vector<Scanner> register_supply_chain_scanners();
std::vector<Scanner> register_advanced_auth_scanners();
std::vector<Scanner> register_power_scanners();
std::vector<Scanner> register_oob_confirmed_scanners();
std::vector<Scanner> register_remaining_web_scanners();
std::vector<Scanner> register_cloud_misconfig_scanners();
std::vector<Scanner> register_secrets_scanners();
std::vector<Scanner> register_ai_infra_scanners();
std::vector<Scanner> register_version_cve_scanners();
std::vector<Scanner> register_ssh_audit_scanners();
std::vector<Scanner> register_cloud_stack_scanners();
std::vector<Scanner> register_deep_recon_scanners();
std::vector<Scanner> register_network_security_scanners();
std::vector<Scanner> register_enterprise_osint_scanners();
std::vector<Scanner> register_interactive_surface_scanners();
std::vector<Scanner> register_otap_scanners();
std::vector<Scanner> register_kvk_scanners();
std::vector<Scanner> register_kev_scanners();
std::vector<Scanner> register_cms_misconfig_scanners();
std::vector<Scanner> register_contact_intel_scanners();
std::vector<Scanner> register_leak_intel_scanners();
std::vector<Scanner> register_shadow_it_scanners();
std::vector<Scanner> register_document_intel_scanners();
std::vector<Scanner> register_version_fingerprint_scanners();
std::vector<Scanner> register_api_discovery_scanners();
std::vector<Scanner> register_advanced_web_scanners();
std::vector<Scanner> register_recon_extra_scanners();
std::vector<Scanner> register_nuclei_scanners();
std::vector<Scanner> register_graphql_hunter();
std::vector<Scanner> register_remaining_web_scanners();
std::vector<Scanner> register_detection_gap_scanners();
std::vector<Scanner> register_bounty_hunter_scanners();
std::vector<Scanner> register_mobile_api_scanners();
std::vector<Scanner> register_infra_misconfig_scanners();
std::vector<Scanner> register_advanced_injection_scanners();
std::vector<Scanner> register_auth_advanced2_scanners();
std::vector<Scanner> register_modern_stack_scanners();
std::vector<Scanner> register_business_logic_scanners();
std::vector<Scanner> register_compliance_scanners();
std::vector<Scanner> register_recon_advanced_scanners();

} // namespace apex

#endif // APEX_SCANNERS_BASE_HPP
namespace apex { std::vector<Scanner> register_wordpress_deep_scanners(); }
namespace apex { std::vector<Scanner> register_app_discovery_scanners(); }
namespace apex { std::vector<Scanner> register_ssrf_deep_scanners(); }
namespace apex { std::vector<Scanner> register_file_upload_scanners(); }
namespace apex { std::vector<Scanner> register_race_condition_scanners(); }
namespace apex { std::vector<Scanner> register_request_smuggling_scanners(); }
namespace apex { std::vector<Scanner> register_cache_poison_scanners(); }
namespace apex { std::vector<Scanner> register_jwt_attack_scanners(); }
namespace apex { std::vector<Scanner> register_graphql_deep_scanners(); }
namespace apex { std::vector<Scanner> register_subdomain_takeover_scanners(); }
namespace apex { std::vector<Scanner> register_oauth_sso_scanners(); }
namespace apex { std::vector<Scanner> register_injection_advanced_scanners(); }
namespace apex { std::vector<Scanner> register_info_disclosure_scanners(); }
namespace apex { std::vector<Scanner> register_attack_chain_scanners(); }
namespace apex { std::vector<Scanner> register_waf_evasion_scanners(); }
namespace apex { std::vector<Scanner> register_exploit_gen_scanners(); }
namespace apex { std::vector<Scanner> register_payload_mutator_scanners(); }
namespace apex { std::vector<Scanner> register_behavioral_analysis_scanners(); }
namespace apex { std::vector<Scanner> register_path_traversal_scanners(); }
namespace apex { std::vector<Scanner> register_browser_engine_scanners(); }
namespace apex { std::vector<Scanner> register_critical_hunter_scanners(); }
namespace apex { std::vector<Scanner> register_cms_specific_scanners(); }
namespace apex { std::vector<Scanner> register_api_protocol_scanners(); }
namespace apex { std::vector<Scanner> register_cloud_attack_scanners(); }
namespace apex { std::vector<Scanner> register_ecommerce_scanners(); }
namespace apex { std::vector<Scanner> register_network_service_scanners(); }
namespace apex { std::vector<Scanner> register_recon_deep2_scanners(); }
namespace apex { std::vector<Scanner> register_auth_scanner_scanners(); }
namespace apex { std::vector<Scanner> register_prototype_pollution_deep_scanners(); }
namespace apex { std::vector<Scanner> register_api_protocol_scanners(); }
namespace apex { std::vector<Scanner> register_ecommerce_scanners(); }namespace apex { std::vector<Scanner> register_autogen_authentication_account_takeover_25_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_idor_broken_access_control_30_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_injection_30_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_business_logic_30_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_file_upload_15_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_api_specific_25_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_infrastructure_cloud_20_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_mobile_client_side_10_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_azure_ad_microsoft_365_20_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_sso_identity_provider_20_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_payment_financial_25_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_email_security_15_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_dns_domain_20_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_api_authentication_20_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_session_management_20_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_input_validation_25_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_file_operations_20_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_cloud_storage_20_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_container_orchestration_15_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_ci_cd_security_15_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_serverless_edge_15_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_mobile_app_security_20_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_rate_limiting_dos_15_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_information_disclosure_extended_25_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_cryptography_15_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_business_logic_extended_25_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_privacy_compliance_15_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_third_party_integration_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_wordpress_deep_20_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_next_js_react_deep_15_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_laravel_php_deep_15_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_django_python_deep_15_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_spring_java_deep_15_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_node_js_express_deep_15_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_oauth_2_0_oidc_deep_15_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_cache_cdn_deep_15_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_http_protocol_15_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_subdomain_dns_extended_15_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_encoding_parser_differential_15_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_monitoring_observability_10_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_ai_llm_security_20_scanners(); }
namespace apex { std::vector<Scanner> register_js_secrets_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_content_sniffing_attacks_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_mime_confusion_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_cookie_manipulation_advanced_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_cookie_scope_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_nosql_injection_advanced_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_request_tunneling_attacks_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_socket_io_abuse_techniques_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_grpc_exploitation_techniques_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_polyglot_file_attacks_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_archive_extraction_attacks_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_class_pollution_attacks_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_relative_path_override_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_smtp_smuggling_attacks_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_html_to_pdf_injection_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_property_injection_attacks_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_http_parameter_fragmentation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_verb_tunneling_method_override_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_error_handling_information_leak_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_debug_endpoint_exposure_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_session_puzzling_attacks_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_session_donation_attacks_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_openid_connect_advanced_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_horizontal_privilege_escalation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_vertical_privilege_escalation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_kubernetes_rbac_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_kubernetes_secrets_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_kubernetes_service_mesh_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_docker_container_escape_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_docker_socket_registry_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_aws_iam_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_aws_ec2_ssrf_metadata_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_gcp_iam_metadata_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_gcp_storage_functions_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_terraform_cloudformation_secrets_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_ci_cd_gitlab_jenkins_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_ipv6_exploitation_techniques_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_dns_exfiltration_tunneling_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_load_balancer_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_reverse_proxy_misconfiguration_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_service_mesh_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_message_queue_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_database_service_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_ldap_server_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_ftp_sftp_misconfiguration_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_snmp_community_string_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_next_js_middleware_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_next_js_rsc_server_actions_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_nuxt_js_vulnerabilities_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_remix_framework_security_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_sveltekit_security_issues_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_astro_ssr_vulnerabilities_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_deno_deploy_security_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_bun_runtime_security_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_edge_computing_attacks_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_serverless_advanced_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_webassembly_security_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_web_push_notification_abuse_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_payment_api_advanced_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_cryptocurrency_wallet_security_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_nft_smart_contract_interaction_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_ai_ml_pipeline_security_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_llm_advanced_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_rag_poisoning_advanced_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_analytics_injection_attacks_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_third_party_script_supply_chain_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_npm_pypi_dependency_confusion_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_github_app_oauth_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_http_2_continuation_attack_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_http_2_protocol_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_http_3_quic_security_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_grpc_security_deep_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_webrtc_security_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_mqtt_security_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_coap_security_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_amqp_security_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_protocol_buffer_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_messagepack_injection_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_thrift_protocol_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_apache_kafka_protocol_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_redis_protocol_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_memcached_protocol_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_mongodb_wire_protocol_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_postgresql_wire_protocol_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_mysql_protocol_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_android_intent_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_android_provider_broadcast_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_ios_url_scheme_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_react_native_security_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_flutter_security_issues_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_capacitor_cordova_security_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_pwa_security_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_electron_app_security_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_chrome_extension_security_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_browser_extension_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_webview_exploitation_techniques_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_mobile_local_storage_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_mobile_ipc_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_gdpr_data_subject_rights_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_pci_dss_compliance_checks_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_hipaa_phi_exposure_detection_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_sox_compliance_testing_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_ccpa_privacy_rights_testing_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_lgpd_brazil_compliance_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_cookie_law_enforcement_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_right_to_erasure_verification_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_consent_management_bypass_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_privacy_policy_compliance_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_wordpress_rest_api_deep_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_wordpress_plugin_exploitation_part1_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_wordpress_plugin_exploitation_part2_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_wordpress_plugin_exploitation_part3_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_wordpress_plugin_exploitation_part4_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_joomla_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_drupal_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_magento_security_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_shopify_security_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_woocommerce_security_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_prestashop_security_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_moodle_security_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_confluence_jira_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_sharepoint_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_salesforce_misconfiguration_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_hubspot_security_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_zendesk_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_servicenow_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_sap_security_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_oracle_ebs_security_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_vmware_vcenter_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_citrix_adc_gateway_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_fortinet_fortigate_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_palo_alto_pan_os_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_sonicwall_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_f5_big_ip_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_ivanti_pulse_secure_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_cisco_asa_ios_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_osint_email_harvesting_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_osint_social_media_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_osint_code_repository_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_osint_domain_history_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_osint_certificate_transparency_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_osint_wayback_machine_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_osint_technology_profiling_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_osint_employee_discovery_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_google_dorking_automation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_shodan_query_integration_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_censys_query_integration_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_securitytrails_integration_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_asn_bgp_analysis_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_ip_range_discovery_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_reverse_dns_enumeration_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_whois_analysis_techniques_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_banner_grabbing_techniques_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_service_fingerprinting_advanced_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_tls_certificate_analysis_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_http_fingerprinting_techniques_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_waf_fingerprinting_advanced_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_cdn_detection_advanced_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_business_logic_exploitation_deep_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_cryptographic_weakness_detection_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_cloud_metadata_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_container_security_advanced_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_api_security_testing_deep_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_zero_day_pattern_detection_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_network_service_discovery_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_cloud_asset_discovery_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_javascript_analysis_intelligence_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_wireless_security_testing_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_iot_device_security_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_active_directory_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_windows_exploitation_techniques_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_linux_exploitation_techniques_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_email_security_testing_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_web_application_firewall_evasion_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_dom_based_vulnerability_detection_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_api_versioning_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_webhook_security_testing_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_microservice_architecture_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_serverless_function_injection_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_database_security_testing_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_log_injection_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_error_based_information_disclosure_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_denial_of_service_patterns_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_session_management_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_security_header_analysis_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_git_repository_security_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_ci_cd_pipeline_security_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_infrastructure_as_code_security_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_container_registry_security_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_kubernetes_network_policy_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_secrets_management_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_monitoring_observability_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_backup_recovery_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_api_documentation_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_single_sign_on_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_headless_browser_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_third_party_integration_security_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_content_injection_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_server_misconfiguration_detection_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_insecure_communication_detection_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_subdomain_security_testing_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_http_security_misconfiguration_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_ssl_tls_vulnerability_detection_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_endpoint_security_testing_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_injection_via_file_processing_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_cloud_function_security_testing_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_dark_web_intelligence_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_phishing_detection_testing_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_network_protocol_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_compliance_automation_testing_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_malware_communication_detection_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_security_monitoring_evasion_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_serverless_event_security_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_identity_federation_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_token_security_testing_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_application_logic_exploitation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_security_architecture_review_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_threat_modeling_automation_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_recon_passive_module_1_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_recon_active_module_2_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_exploit_mobile_module_4_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_exploit_cloud_module_5_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_exploit_auth_module_8_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_exploit_session_module_9_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_exploit_file_module_10_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_exploit_inject_module_11_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_exploit_logic_module_12_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_exploit_config_module_13_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_exploit_crypto_module_14_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_exploit_cache_module_15_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_scanner_http_module_16_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_scanner_tls_module_18_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_scanner_port_module_19_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_scanner_waf_module_21_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_scanner_cdn_module_22_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_scanner_cms_module_23_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_scanner_cloud_module_25_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_audit_access_module_26_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_audit_config_module_28_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_hunter_privesc_module_32_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_hunter_race_module_33_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_hunter_logic_module_34_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_hunter_chain_module_35_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_intel_osint_module_36_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_intel_threat_module_37_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_intel_vuln_module_38_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_intel_asset_module_39_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_intel_breach_module_40_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_detect_anomaly_module_41_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_detect_pattern_module_42_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_detect_signature_module_43_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_detect_behavior_module_44_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_detect_evasion_module_45_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_fuzz_input_module_46_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_fuzz_protocol_module_47_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_fuzz_format_module_48_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_fuzz_binary_module_50_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_verify_patch_module_51_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_verify_config_module_52_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_verify_deploy_module_53_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_verify_access_module_54_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_verify_encrypt_module_55_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_assess_risk_module_56_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_assess_likelihood_module_58_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_assess_surface_module_59_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_assess_depth_module_60_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_pentest_external_module_61_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_pentest_internal_module_62_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_pentest_social_module_64_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_pentest_physical_module_65_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_red_team_persist_module_66_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_red_team_lateral_module_67_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_red_team_exfil_module_68_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_red_team_c2_module_69_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_red_team_evasion_module_70_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_blue_team_alert_module_71_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_blue_team_response_module_72_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_blue_team_contain_module_73_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_blue_team_recover_module_74_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_blue_team_hunt_module_75_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_vuln_scan_web_module_76_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_vuln_scan_infra_module_77_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_vuln_scan_code_module_79_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_vuln_scan_dep_module_80_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_hardening_os_module_86_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_hardening_db_module_88_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_hardening_net_module_89_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_hardening_cloud_module_90_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_forensic_memory_module_91_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_forensic_disk_module_92_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_forensic_log_module_94_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_forensic_timeline_module_95_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_maturity_owasp_module_96_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_maturity_nist_module_97_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_maturity_iso_module_98_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_maturity_bsimm_module_99_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_maturity_samm_module_100_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_apex_zero_click_rce_assessment_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_apex_firmware_backdoor_assessment_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_apex_heap_spray_assessment_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_apex_use_after_free_assessment_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_apex_buffer_overrun_assessment_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_apex_stack_pivot_assessment_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_apex_rop_chain_assessment_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_apex_jit_spray_assessment_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_apex_v8_exploit_assessment_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_apex_spectre_meltdown_assessment_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_apex_rowhammer_assessment_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_apex_power_analysis_assessment_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_apex_electromagnetic_assessment_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_apex_acoustic_crypto_assessment_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_apex_thermal_monitor_assessment_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_apex_quantum_ready_assessment_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_apex_deepfake_detection_protocol_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_apex_gps_spoofing_protocol_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_apex_rf_jamming_protocol_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_apex_ultrasonic_attack_protocol_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_apex_laser_inject_protocol_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_apex_emi_glitch_protocol_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_apex_voltage_fault_protocol_12_scanners(); }
namespace apex { std::vector<Scanner> register_autogen_apex_photon_emit_protocol_12_scanners(); }
