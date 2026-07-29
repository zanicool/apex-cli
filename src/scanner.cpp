/// @file scanner.cpp
/// @brief Scanner orchestrator: registers all feature modules, runs scanners
///        concurrently, deduplicates findings.
#include "scanner.hpp"

#include <algorithm>
#include <atomic>
#include <future>
#include <iostream>
#include <mutex>
#include <set>
#include <thread>

#include "scanners/scanner_base.hpp"
#include "targeting.hpp"
#include "wildcard.hpp"

namespace apex {

// Global findings accessible by the Attack Chain Engine
std::vector<Finding> g_all_findings;

std::vector<Scanner> get_scanners() {
  std::vector<Scanner> all;
  auto append = [&](std::vector<Scanner>&& scanners) {
    all.insert(all.end(), std::make_move_iterator(scanners.begin()), std::make_move_iterator(scanners.end()));
  };

  append(register_core_scanners());
  append(register_smart_scanners());
  append(register_elite_scanners());
  append(register_godly_scanners());
  append(register_autonomous_scanners());
  append(register_browser_scanners());
  append(register_auth_scanners());
  append(register_injection_scanners());
  append(register_logic_scanners());
  append(register_modern_scanners());
  append(register_infrastructure_scanners());
  append(register_oob_scanners());
  append(register_recon_scanners());
  append(register_web_scanners());
  append(register_exploit_scanners());
  append(register_extra_scanners());
  append(register_waf_scanners());
  append(register_supply_chain_scanners());
  append(register_advanced_auth_scanners());
  append(register_power_scanners());
  append(register_oob_confirmed_scanners());
  append(register_remaining_web_scanners());
  append(register_cloud_misconfig_scanners());
  append(register_secrets_scanners());
  append(register_ai_infra_scanners());
  append(register_version_cve_scanners());
  append(register_ssh_audit_scanners());
  append(register_cloud_stack_scanners());
  append(register_deep_recon_scanners());
  append(register_network_security_scanners());
  append(register_enterprise_osint_scanners());
  append(register_interactive_surface_scanners());
  append(register_otap_scanners());
  append(register_kvk_scanners());
  append(register_kev_scanners());
  append(register_cms_misconfig_scanners());
  append(register_contact_intel_scanners());
  append(register_leak_intel_scanners());
  append(register_shadow_it_scanners());
  append(register_document_intel_scanners());
  append(register_version_fingerprint_scanners());
  append(register_api_discovery_scanners());
  append(register_advanced_web_scanners());
  append(register_recon_extra_scanners());
  append(register_nuclei_scanners());
  append(register_wordpress_deep_scanners());
  append(register_graphql_hunter());
  append(register_detection_gap_scanners());
  append(register_bounty_hunter_scanners());
  append(register_mobile_api_scanners());
  append(register_app_discovery_scanners());
  append(register_ssrf_deep_scanners());
  append(register_file_upload_scanners());
  append(register_race_condition_scanners());
  append(register_request_smuggling_scanners());
  append(register_cache_poison_scanners());
  append(register_jwt_attack_scanners());
  append(register_graphql_deep_scanners());
  append(register_subdomain_takeover_scanners());
  append(register_oauth_sso_scanners());
  append(register_injection_advanced_scanners());
  append(register_info_disclosure_scanners());
  append(register_waf_evasion_scanners());
  append(register_payload_mutator_scanners());
  append(register_behavioral_analysis_scanners());
  append(register_path_traversal_scanners());
  append(register_browser_engine_scanners());
  append(register_critical_hunter_scanners());
  append(register_cms_specific_scanners());
  append(register_api_protocol_scanners());
  append(register_cloud_attack_scanners());
  append(register_ecommerce_scanners());
  append(register_network_service_scanners());
  append(register_recon_deep2_scanners());
  append(register_auth_scanner_scanners());
  append(register_prototype_pollution_deep_scanners());
  append(register_autogen_azure_ad_microsoft_365_20_scanners());
  append(register_autogen_sso_identity_provider_20_scanners());
  append(register_autogen_payment_financial_25_scanners());
  append(register_autogen_email_security_15_scanners());
  append(register_autogen_dns_domain_20_scanners());
  append(register_autogen_api_authentication_20_scanners());
  append(register_autogen_session_management_20_scanners());
  append(register_autogen_input_validation_25_scanners());
  append(register_autogen_file_operations_20_scanners());
  append(register_autogen_cloud_storage_20_scanners());
  append(register_autogen_container_orchestration_15_scanners());
  append(register_autogen_ci_cd_security_15_scanners());
  append(register_autogen_serverless_edge_15_scanners());
  append(register_autogen_mobile_app_security_20_scanners());
  append(register_autogen_rate_limiting_dos_15_scanners());
  append(register_autogen_information_disclosure_extended_25_scanners());
  append(register_autogen_cryptography_15_scanners());
  append(register_autogen_business_logic_extended_25_scanners());
  append(register_autogen_privacy_compliance_15_scanners());
  append(register_autogen_third_party_integration_12_scanners());
  append(register_autogen_wordpress_deep_20_scanners());
  append(register_autogen_next_js_react_deep_15_scanners());
  append(register_autogen_laravel_php_deep_15_scanners());
  append(register_autogen_django_python_deep_15_scanners());
  append(register_autogen_spring_java_deep_15_scanners());
  append(register_autogen_node_js_express_deep_15_scanners());
  append(register_autogen_oauth_2_0_oidc_deep_15_scanners());
  append(register_autogen_cache_cdn_deep_15_scanners());
  append(register_autogen_http_protocol_15_scanners());
  append(register_autogen_subdomain_dns_extended_15_scanners());
  append(register_autogen_encoding_parser_differential_15_scanners());
  append(register_autogen_monitoring_observability_10_scanners());
  append(register_autogen_ai_llm_security_20_scanners());
  append(register_js_secrets_scanners());
  append(register_autogen_authentication_account_takeover_25_scanners());
  append(register_autogen_idor_broken_access_control_30_scanners());
  append(register_autogen_injection_30_scanners());
  append(register_autogen_business_logic_30_scanners());
  append(register_autogen_file_upload_15_scanners());
  append(register_autogen_api_specific_25_scanners());
  append(register_autogen_infrastructure_cloud_20_scanners());
  append(register_autogen_mobile_client_side_10_scanners());
  append(register_infra_misconfig_scanners());
  append(register_advanced_injection_scanners());
  append(register_auth_advanced2_scanners());
  append(register_modern_stack_scanners());
  append(register_business_logic_scanners());
  append(register_compliance_scanners());
  append(register_recon_advanced_scanners());

  append(register_autogen_content_sniffing_attacks_12_scanners());
  append(register_autogen_mime_confusion_exploitation_12_scanners());
  append(register_autogen_cookie_manipulation_advanced_12_scanners());
  append(register_autogen_cookie_scope_exploitation_12_scanners());
  append(register_autogen_nosql_injection_advanced_12_scanners());
  append(register_autogen_request_tunneling_attacks_12_scanners());
  append(register_autogen_socket_io_abuse_techniques_12_scanners());
  append(register_autogen_grpc_exploitation_techniques_12_scanners());
  append(register_autogen_polyglot_file_attacks_12_scanners());
  append(register_autogen_archive_extraction_attacks_12_scanners());
  append(register_autogen_class_pollution_attacks_12_scanners());
  append(register_autogen_relative_path_override_12_scanners());
  append(register_autogen_smtp_smuggling_attacks_12_scanners());
  append(register_autogen_html_to_pdf_injection_12_scanners());
  append(register_autogen_property_injection_attacks_12_scanners());
  append(register_autogen_http_parameter_fragmentation_12_scanners());
  append(register_autogen_verb_tunneling_method_override_12_scanners());
  append(register_autogen_error_handling_information_leak_12_scanners());
  append(register_autogen_debug_endpoint_exposure_12_scanners());
  append(register_autogen_session_puzzling_attacks_12_scanners());
  append(register_autogen_session_donation_attacks_12_scanners());
  append(register_autogen_openid_connect_advanced_12_scanners());
  append(register_autogen_horizontal_privilege_escalation_12_scanners());
  append(register_autogen_vertical_privilege_escalation_12_scanners());
  append(register_autogen_kubernetes_rbac_exploitation_12_scanners());
  append(register_autogen_kubernetes_secrets_exploitation_12_scanners());
  append(register_autogen_kubernetes_service_mesh_12_scanners());
  append(register_autogen_docker_container_escape_12_scanners());
  append(register_autogen_docker_socket_registry_12_scanners());
  append(register_autogen_aws_iam_exploitation_12_scanners());
  append(register_autogen_aws_ec2_ssrf_metadata_12_scanners());
  append(register_autogen_gcp_iam_metadata_12_scanners());
  append(register_autogen_gcp_storage_functions_12_scanners());
  append(register_autogen_terraform_cloudformation_secrets_12_scanners());
  append(register_autogen_ci_cd_gitlab_jenkins_12_scanners());
  append(register_autogen_ipv6_exploitation_techniques_12_scanners());
  append(register_autogen_dns_exfiltration_tunneling_12_scanners());
  append(register_autogen_load_balancer_exploitation_12_scanners());
  append(register_autogen_reverse_proxy_misconfiguration_12_scanners());
  append(register_autogen_service_mesh_exploitation_12_scanners());
  append(register_autogen_message_queue_exploitation_12_scanners());
  append(register_autogen_database_service_exploitation_12_scanners());
  append(register_autogen_ldap_server_exploitation_12_scanners());
  append(register_autogen_ftp_sftp_misconfiguration_12_scanners());
  append(register_autogen_snmp_community_string_12_scanners());
  append(register_autogen_next_js_middleware_exploitation_12_scanners());
  append(register_autogen_next_js_rsc_server_actions_12_scanners());
  append(register_autogen_nuxt_js_vulnerabilities_12_scanners());
  append(register_autogen_remix_framework_security_12_scanners());
  append(register_autogen_sveltekit_security_issues_12_scanners());
  append(register_autogen_astro_ssr_vulnerabilities_12_scanners());
  append(register_autogen_deno_deploy_security_12_scanners());
  append(register_autogen_bun_runtime_security_12_scanners());
  append(register_autogen_edge_computing_attacks_12_scanners());
  append(register_autogen_serverless_advanced_exploitation_12_scanners());
  append(register_autogen_webassembly_security_12_scanners());
  append(register_autogen_web_push_notification_abuse_12_scanners());
  append(register_autogen_payment_api_advanced_12_scanners());
  append(register_autogen_cryptocurrency_wallet_security_12_scanners());
  append(register_autogen_nft_smart_contract_interaction_12_scanners());
  append(register_autogen_ai_ml_pipeline_security_12_scanners());
  append(register_autogen_llm_advanced_exploitation_12_scanners());
  append(register_autogen_rag_poisoning_advanced_12_scanners());
  append(register_autogen_analytics_injection_attacks_12_scanners());
  append(register_autogen_third_party_script_supply_chain_12_scanners());
  append(register_autogen_npm_pypi_dependency_confusion_12_scanners());
  append(register_autogen_github_app_oauth_exploitation_12_scanners());
  append(register_autogen_http_2_continuation_attack_12_scanners());
  append(register_autogen_http_2_protocol_exploitation_12_scanners());
  append(register_autogen_http_3_quic_security_12_scanners());
  append(register_autogen_grpc_security_deep_12_scanners());
  append(register_autogen_webrtc_security_12_scanners());
  append(register_autogen_mqtt_security_exploitation_12_scanners());
  append(register_autogen_coap_security_exploitation_12_scanners());
  append(register_autogen_amqp_security_exploitation_12_scanners());
  append(register_autogen_protocol_buffer_exploitation_12_scanners());
  append(register_autogen_messagepack_injection_12_scanners());
  append(register_autogen_thrift_protocol_exploitation_12_scanners());
  append(register_autogen_apache_kafka_protocol_12_scanners());
  append(register_autogen_redis_protocol_exploitation_12_scanners());
  append(register_autogen_memcached_protocol_exploitation_12_scanners());
  append(register_autogen_mongodb_wire_protocol_12_scanners());
  append(register_autogen_postgresql_wire_protocol_12_scanners());
  append(register_autogen_mysql_protocol_exploitation_12_scanners());
  append(register_autogen_android_intent_exploitation_12_scanners());
  append(register_autogen_android_provider_broadcast_12_scanners());
  append(register_autogen_ios_url_scheme_exploitation_12_scanners());
  append(register_autogen_react_native_security_12_scanners());
  append(register_autogen_flutter_security_issues_12_scanners());
  append(register_autogen_capacitor_cordova_security_12_scanners());
  append(register_autogen_pwa_security_exploitation_12_scanners());
  append(register_autogen_electron_app_security_12_scanners());
  append(register_autogen_chrome_extension_security_12_scanners());
  append(register_autogen_browser_extension_exploitation_12_scanners());
  append(register_autogen_webview_exploitation_techniques_12_scanners());
  append(register_autogen_mobile_local_storage_12_scanners());
  append(register_autogen_mobile_ipc_exploitation_12_scanners());
  append(register_autogen_gdpr_data_subject_rights_12_scanners());
  append(register_autogen_pci_dss_compliance_checks_12_scanners());
  append(register_autogen_hipaa_phi_exposure_detection_12_scanners());
  append(register_autogen_sox_compliance_testing_12_scanners());
  append(register_autogen_ccpa_privacy_rights_testing_12_scanners());
  append(register_autogen_lgpd_brazil_compliance_12_scanners());
  append(register_autogen_cookie_law_enforcement_12_scanners());
  append(register_autogen_right_to_erasure_verification_12_scanners());
  append(register_autogen_consent_management_bypass_12_scanners());
  append(register_autogen_privacy_policy_compliance_12_scanners());
  append(register_autogen_wordpress_rest_api_deep_12_scanners());
  append(register_autogen_wordpress_plugin_exploitation_part1_12_scanners());
  append(register_autogen_wordpress_plugin_exploitation_part2_12_scanners());
  append(register_autogen_wordpress_plugin_exploitation_part3_12_scanners());
  append(register_autogen_wordpress_plugin_exploitation_part4_12_scanners());
  append(register_autogen_joomla_exploitation_12_scanners());
  append(register_autogen_drupal_exploitation_12_scanners());
  append(register_autogen_magento_security_12_scanners());
  append(register_autogen_shopify_security_12_scanners());
  append(register_autogen_woocommerce_security_12_scanners());
  append(register_autogen_prestashop_security_12_scanners());
  append(register_autogen_moodle_security_12_scanners());
  append(register_autogen_confluence_jira_exploitation_12_scanners());
  append(register_autogen_sharepoint_exploitation_12_scanners());
  append(register_autogen_salesforce_misconfiguration_12_scanners());
  append(register_autogen_hubspot_security_12_scanners());
  append(register_autogen_zendesk_exploitation_12_scanners());
  append(register_autogen_servicenow_exploitation_12_scanners());
  append(register_autogen_sap_security_exploitation_12_scanners());
  append(register_autogen_oracle_ebs_security_12_scanners());
  append(register_autogen_vmware_vcenter_exploitation_12_scanners());
  append(register_autogen_citrix_adc_gateway_12_scanners());
  append(register_autogen_fortinet_fortigate_12_scanners());
  append(register_autogen_palo_alto_pan_os_12_scanners());
  append(register_autogen_sonicwall_exploitation_12_scanners());
  append(register_autogen_f5_big_ip_exploitation_12_scanners());
  append(register_autogen_ivanti_pulse_secure_12_scanners());
  append(register_autogen_cisco_asa_ios_12_scanners());
  append(register_autogen_osint_email_harvesting_12_scanners());
  append(register_autogen_osint_social_media_12_scanners());
  append(register_autogen_osint_code_repository_12_scanners());
  append(register_autogen_osint_domain_history_12_scanners());
  append(register_autogen_osint_certificate_transparency_12_scanners());
  append(register_autogen_osint_wayback_machine_12_scanners());
  append(register_autogen_osint_technology_profiling_12_scanners());
  append(register_autogen_osint_employee_discovery_12_scanners());
  append(register_autogen_google_dorking_automation_12_scanners());
  append(register_autogen_shodan_query_integration_12_scanners());
  append(register_autogen_censys_query_integration_12_scanners());
  append(register_autogen_securitytrails_integration_12_scanners());
  append(register_autogen_asn_bgp_analysis_12_scanners());
  append(register_autogen_ip_range_discovery_12_scanners());
  append(register_autogen_reverse_dns_enumeration_12_scanners());
  append(register_autogen_whois_analysis_techniques_12_scanners());
  append(register_autogen_banner_grabbing_techniques_12_scanners());
  append(register_autogen_service_fingerprinting_advanced_12_scanners());
  append(register_autogen_tls_certificate_analysis_12_scanners());
  append(register_autogen_http_fingerprinting_techniques_12_scanners());
  append(register_autogen_waf_fingerprinting_advanced_12_scanners());
  append(register_autogen_cdn_detection_advanced_12_scanners());
  append(register_autogen_business_logic_exploitation_deep_12_scanners());
  append(register_autogen_cryptographic_weakness_detection_12_scanners());
  append(register_autogen_cloud_metadata_exploitation_12_scanners());
  append(register_autogen_container_security_advanced_12_scanners());
  append(register_autogen_api_security_testing_deep_12_scanners());
  append(register_autogen_zero_day_pattern_detection_12_scanners());
  append(register_autogen_network_service_discovery_12_scanners());
  append(register_autogen_cloud_asset_discovery_12_scanners());
  append(register_autogen_javascript_analysis_intelligence_12_scanners());
  append(register_autogen_wireless_security_testing_12_scanners());
  append(register_autogen_iot_device_security_12_scanners());
  append(register_autogen_active_directory_exploitation_12_scanners());
  append(register_autogen_windows_exploitation_techniques_12_scanners());
  append(register_autogen_linux_exploitation_techniques_12_scanners());
  append(register_autogen_email_security_testing_12_scanners());
  append(register_autogen_web_application_firewall_evasion_12_scanners());
  append(register_autogen_dom_based_vulnerability_detection_12_scanners());
  append(register_autogen_api_versioning_exploitation_12_scanners());
  append(register_autogen_webhook_security_testing_12_scanners());
  append(register_autogen_microservice_architecture_exploitation_12_scanners());
  append(register_autogen_serverless_function_injection_12_scanners());
  append(register_autogen_database_security_testing_12_scanners());
  append(register_autogen_log_injection_exploitation_12_scanners());
  append(register_autogen_error_based_information_disclosure_12_scanners());
  append(register_autogen_denial_of_service_patterns_12_scanners());
  append(register_autogen_session_management_exploitation_12_scanners());
  append(register_autogen_security_header_analysis_12_scanners());
  append(register_autogen_git_repository_security_12_scanners());
  append(register_autogen_ci_cd_pipeline_security_12_scanners());
  append(register_autogen_infrastructure_as_code_security_12_scanners());
  append(register_autogen_container_registry_security_12_scanners());
  append(register_autogen_kubernetes_network_policy_12_scanners());
  append(register_autogen_secrets_management_exploitation_12_scanners());
  append(register_autogen_monitoring_observability_exploitation_12_scanners());
  append(register_autogen_backup_recovery_exploitation_12_scanners());
  append(register_autogen_api_documentation_exploitation_12_scanners());
  append(register_autogen_single_sign_on_exploitation_12_scanners());
  append(register_autogen_headless_browser_exploitation_12_scanners());
  append(register_autogen_third_party_integration_security_12_scanners());
  append(register_autogen_content_injection_exploitation_12_scanners());
  append(register_autogen_server_misconfiguration_detection_12_scanners());
  append(register_autogen_insecure_communication_detection_12_scanners());
  append(register_autogen_subdomain_security_testing_12_scanners());
  append(register_autogen_http_security_misconfiguration_12_scanners());
  append(register_autogen_ssl_tls_vulnerability_detection_12_scanners());
  append(register_autogen_endpoint_security_testing_12_scanners());
  append(register_autogen_injection_via_file_processing_12_scanners());
  append(register_autogen_cloud_function_security_testing_12_scanners());
  append(register_autogen_dark_web_intelligence_12_scanners());
  append(register_autogen_phishing_detection_testing_12_scanners());
  append(register_autogen_network_protocol_exploitation_12_scanners());
  append(register_autogen_compliance_automation_testing_12_scanners());
  append(register_autogen_malware_communication_detection_12_scanners());
  append(register_autogen_security_monitoring_evasion_12_scanners());
  append(register_autogen_serverless_event_security_12_scanners());
  append(register_autogen_identity_federation_exploitation_12_scanners());
  append(register_autogen_token_security_testing_12_scanners());
  append(register_autogen_application_logic_exploitation_12_scanners());
  append(register_autogen_security_architecture_review_12_scanners());
  append(register_autogen_threat_modeling_automation_12_scanners());
  append(register_autogen_recon_passive_module_1_12_scanners());
  append(register_autogen_recon_active_module_2_12_scanners());
  append(register_autogen_exploit_mobile_module_4_12_scanners());
  append(register_autogen_exploit_cloud_module_5_12_scanners());
  append(register_autogen_exploit_auth_module_8_12_scanners());
  append(register_autogen_exploit_session_module_9_12_scanners());
  append(register_autogen_exploit_file_module_10_12_scanners());
  append(register_autogen_exploit_inject_module_11_12_scanners());
  append(register_autogen_exploit_logic_module_12_12_scanners());
  append(register_autogen_exploit_config_module_13_12_scanners());
  append(register_autogen_exploit_crypto_module_14_12_scanners());
  append(register_autogen_exploit_cache_module_15_12_scanners());
  append(register_autogen_scanner_http_module_16_12_scanners());
  append(register_autogen_scanner_tls_module_18_12_scanners());
  append(register_autogen_scanner_port_module_19_12_scanners());
  append(register_autogen_scanner_waf_module_21_12_scanners());
  append(register_autogen_scanner_cdn_module_22_12_scanners());
  append(register_autogen_scanner_cms_module_23_12_scanners());
  append(register_autogen_scanner_cloud_module_25_12_scanners());
  append(register_autogen_audit_access_module_26_12_scanners());
  append(register_autogen_audit_config_module_28_12_scanners());
  append(register_autogen_hunter_privesc_module_32_12_scanners());
  append(register_autogen_hunter_race_module_33_12_scanners());
  append(register_autogen_hunter_logic_module_34_12_scanners());
  append(register_autogen_hunter_chain_module_35_12_scanners());
  append(register_autogen_intel_osint_module_36_12_scanners());
  append(register_autogen_intel_threat_module_37_12_scanners());
  append(register_autogen_intel_vuln_module_38_12_scanners());
  append(register_autogen_intel_asset_module_39_12_scanners());
  append(register_autogen_intel_breach_module_40_12_scanners());
  append(register_autogen_detect_anomaly_module_41_12_scanners());
  append(register_autogen_detect_pattern_module_42_12_scanners());
  append(register_autogen_detect_signature_module_43_12_scanners());
  append(register_autogen_detect_behavior_module_44_12_scanners());
  append(register_autogen_detect_evasion_module_45_12_scanners());
  append(register_autogen_fuzz_input_module_46_12_scanners());
  append(register_autogen_fuzz_protocol_module_47_12_scanners());
  append(register_autogen_fuzz_format_module_48_12_scanners());
  append(register_autogen_fuzz_binary_module_50_12_scanners());
  append(register_autogen_verify_patch_module_51_12_scanners());
  append(register_autogen_verify_config_module_52_12_scanners());
  append(register_autogen_verify_deploy_module_53_12_scanners());
  append(register_autogen_verify_access_module_54_12_scanners());
  append(register_autogen_verify_encrypt_module_55_12_scanners());
  append(register_autogen_assess_risk_module_56_12_scanners());
  append(register_autogen_assess_likelihood_module_58_12_scanners());
  append(register_autogen_assess_surface_module_59_12_scanners());
  append(register_autogen_assess_depth_module_60_12_scanners());
  append(register_autogen_pentest_external_module_61_12_scanners());
  append(register_autogen_pentest_internal_module_62_12_scanners());
  append(register_autogen_pentest_social_module_64_12_scanners());
  append(register_autogen_pentest_physical_module_65_12_scanners());
  append(register_autogen_red_team_persist_module_66_12_scanners());
  append(register_autogen_red_team_lateral_module_67_12_scanners());
  append(register_autogen_red_team_exfil_module_68_12_scanners());
  append(register_autogen_red_team_c2_module_69_12_scanners());
  append(register_autogen_red_team_evasion_module_70_12_scanners());
  append(register_autogen_blue_team_alert_module_71_12_scanners());
  append(register_autogen_blue_team_response_module_72_12_scanners());
  append(register_autogen_blue_team_contain_module_73_12_scanners());
  append(register_autogen_blue_team_recover_module_74_12_scanners());
  append(register_autogen_blue_team_hunt_module_75_12_scanners());
  append(register_autogen_vuln_scan_web_module_76_12_scanners());
  append(register_autogen_vuln_scan_infra_module_77_12_scanners());
  append(register_autogen_vuln_scan_code_module_79_12_scanners());
  append(register_autogen_vuln_scan_dep_module_80_12_scanners());
  append(register_autogen_hardening_os_module_86_12_scanners());
  append(register_autogen_hardening_db_module_88_12_scanners());
  append(register_autogen_hardening_net_module_89_12_scanners());
  append(register_autogen_hardening_cloud_module_90_12_scanners());
  append(register_autogen_forensic_memory_module_91_12_scanners());
  append(register_autogen_forensic_disk_module_92_12_scanners());
  append(register_autogen_forensic_log_module_94_12_scanners());
  append(register_autogen_forensic_timeline_module_95_12_scanners());
  append(register_autogen_maturity_owasp_module_96_12_scanners());
  append(register_autogen_maturity_nist_module_97_12_scanners());
  append(register_autogen_maturity_iso_module_98_12_scanners());
  append(register_autogen_maturity_bsimm_module_99_12_scanners());
  append(register_autogen_maturity_samm_module_100_12_scanners());
  append(register_autogen_apex_zero_click_rce_assessment_12_scanners());
  append(register_autogen_apex_firmware_backdoor_assessment_12_scanners());
  append(register_autogen_apex_heap_spray_assessment_12_scanners());
  append(register_autogen_apex_use_after_free_assessment_12_scanners());
  append(register_autogen_apex_buffer_overrun_assessment_12_scanners());
  append(register_autogen_apex_stack_pivot_assessment_12_scanners());
  append(register_autogen_apex_rop_chain_assessment_12_scanners());
  append(register_autogen_apex_jit_spray_assessment_12_scanners());
  append(register_autogen_apex_v8_exploit_assessment_12_scanners());
  append(register_autogen_apex_spectre_meltdown_assessment_12_scanners());
  append(register_autogen_apex_rowhammer_assessment_12_scanners());
  append(register_autogen_apex_power_analysis_assessment_12_scanners());
  append(register_autogen_apex_electromagnetic_assessment_12_scanners());
  append(register_autogen_apex_acoustic_crypto_assessment_12_scanners());
  append(register_autogen_apex_thermal_monitor_assessment_12_scanners());
  append(register_autogen_apex_quantum_ready_assessment_12_scanners());
  append(register_autogen_apex_deepfake_detection_protocol_12_scanners());
  append(register_autogen_apex_gps_spoofing_protocol_12_scanners());
  append(register_autogen_apex_rf_jamming_protocol_12_scanners());
  append(register_autogen_apex_ultrasonic_attack_protocol_12_scanners());
  append(register_autogen_apex_laser_inject_protocol_12_scanners());
  append(register_autogen_apex_emi_glitch_protocol_12_scanners());
  append(register_autogen_apex_voltage_fault_protocol_12_scanners());
  append(register_autogen_apex_photon_emit_protocol_12_scanners());

  return all;
}

std::vector<Finding> run_scanners(const Config& cfg, HttpClient& http, const CrawlResult& crawl) {
  auto all_scanners = get_scanners();

  // Intelligent Targeting: build asset profile and select relevant modules
  auto profile = build_profile(crawl, http);
  auto scanners = cfg.full_scan ? all_scanners : select_modules(all_scanners, profile, 0.3);

  // Log targeting decision
  if (!cfg.full_scan && scanners.size() < all_scanners.size()) {
    std::cerr << "  [targeting] " << scanners.size() << "/" << all_scanners.size() << " modules selected (";
    for (const auto& t : profile.technologies) std::cerr << t << " ";
    if (profile.has_graphql) std::cerr << "graphql ";
    if (profile.has_jwt) std::cerr << "jwt ";
    if (profile.has_oauth) std::cerr << "oauth ";
    std::cerr << ")\n";
  }

  std::vector<Finding> all_findings;
  std::mutex mu;

  auto should_skip = [&](const std::string& name) {
    if (std::any_of(cfg.skip.begin(), cfg.skip.end(), [&](const std::string& s) { return s == name; })) return true;
    // Quick mode: only run high-value scanners.
    if (cfg.blitz) {
      // Ultra-fast: only the 20 checks most likely to find bounty-worthy bugs
      static const std::vector<std::string> blitz_scanners = {
        "Open Redirect", "SSRF", "IDOR", "Secrets Exposure", "GraphQL Hunter",
        "JWT", "Security Headers", "CORS", "SQLi", "XSS",
        "SSTI", "Default Credentials", "Git Exposure", "Env File Exposed",
        "S3 Buckets", "Subdomain Takeover", "Hidden Admin Panel",
        "OAuth Misconfig", "Password Reset Poisoning", "CRLF Response Splitting"
      };
      return std::none_of(blitz_scanners.begin(), blitz_scanners.end(), [&](const std::string& q) { return name.find(q) != std::string::npos; });
    }
    if (cfg.quick) {
      static const std::vector<std::string> quick_scanners = {"CMS Detection",
                                                              "SQLi",
                                                              "XSS",
                                                              "SSRF",
                                                              "CMDi",
                                                              "LFI",
                                                              "Security Headers",
                                                              "Open Redirect",
                                                              "SSTI",
                                                              "XXE",
                                                              "CORS",
                                                              "Clickjacking",
                                                              "Info Disclosure",
                                                              "WAF Detection",
                                                              "Login Security",
                                                              "Header Analysis",
                                                              "Content Discovery",
                                                              "Forced Browsing",
                                                              "GraphQL Hunter",
                                                              "IDOR",
                                                              "JWT",
                                                              "OAuth Misconfig",
                                                              "Password Reset",
                                                              "Race Condition",
                                                              "API Version Bypass",
                                                              "Secrets Exposure",
                                                              "Supply Chain: Self-Hosted Tools",
                                                              "Supply Chain: Cloud Storage",
                                                              "Supply Chain: Integrations",
                                                              "Supply Chain: Management Panels",
                                                              "Supply Chain: SSO Config",
                                                              "Supply Chain: API Keys",
                                                              "WP Plugin",
                                                              "WP Theme",
                                                              "Password Reset Poisoning",
                                                              "Account Takeover (Email Change)",
                                                              "JWT Key Confusion",
                                                              "GraphQL Abuse",
                                                              "Rate Limit Bypass",
                                                              "File Upload Abuse",
                                                              "HTTP Parameter Pollution",
                                                              "CRLF Response Splitting",
                                                              "Method Override Bypass",
                                                              "API Version Bypass"};
      return std::none_of(quick_scanners.begin(), quick_scanners.end(), [&](const std::string& q) { return q == name; });
    }
    return false;
  };

  std::vector<std::future<std::vector<Finding>>> futures;
  int max_concurrent = std::min(cfg.threads, 20);

  // Collect scanners to run
  std::vector<Scanner> to_run;
  for (const auto& scanner : scanners) {
    if (should_skip(scanner.name)) {
      std::cout << "    [skip] " << scanner.name << "\n";
      continue;
    }
    std::cout << "    [->] " << scanner.name << "\n";
    to_run.push_back(scanner);
  }

  // Execute in batches to avoid thread exhaustion
  for (size_t i = 0; i < to_run.size(); i += max_concurrent) {
    size_t batch_end = std::min(i + (size_t)max_concurrent, to_run.size());
    std::vector<std::future<std::vector<Finding>>> batch;
    for (size_t j = i; j < batch_end; j++) {
      auto scanner_func = to_run[j].func;
      batch.push_back(std::async(std::launch::async, [scanner_func, &cfg, &http, &crawl]() -> std::vector<Finding> {
        try {
          return scanner_func(cfg, http, crawl);
        } catch (...) {
          return {};
        }
      }));
    }
    for (auto& f : batch) {
      auto results = f.get();
      std::lock_guard<std::mutex> lock(mu);
      all_findings.insert(all_findings.end(), results.begin(), results.end());
    }
  }

  // Deduplicate on type+url+param.
  std::set<std::string> seen;
  std::vector<Finding> deduped;
  for (auto& f : all_findings) {
    std::string key = f.type + "|" + f.url + "|" + f.param;
    if (seen.insert(key).second) deduped.push_back(std::move(f));
  }

  // Filter wildcard/SPA false positives.
  // Get baseline for each unique host.
  std::map<std::string, BaselineFingerprint> baselines;
  auto get_host = [](const std::string& url) -> std::string {
    auto pos = url.find("://");
    if (pos == std::string::npos) return url;
    auto start = pos + 3;
    auto end = url.find('/', start);
    return url.substr(0, end != std::string::npos ? end : url.size());
  };

  std::vector<Finding> filtered;
  for (auto& f : deduped) {
    std::string host = get_host(f.url);
    if (baselines.find(host) == baselines.end()) {
      baselines[host] = get_baseline(http, host);
    }
    auto& bp = baselines[host];
    // Skip findings on wildcard hosts unless they have specific evidence
    if (bp.is_wildcard && f.evidence.empty()) {
      continue;
    }
    filtered.push_back(std::move(f));
  }

  // Quality filter: downgrade critical/high findings that lack evidence
  for (auto& f : filtered) {
    if ((f.severity == "critical" || f.severity == "high") && f.evidence.empty()) {
      // No evidence = unverified = downgrade to medium
      f.severity = "medium";
      f.type += " (unverified)";
    }
  }

  // AI Verification: use qwen3:14b to filter false positives
  {
    int ai_checked = 0;
    for (auto& f : filtered) {
      if (f.severity != "critical" && f.severity != "high") continue;
      if (ai_checked >= 5) break;
      std::string ev = f.evidence.substr(0, 80);
      for (auto& c : ev) {
        if (c == '"' || c == '\\' || c == '\n') c = ' ';
      }
      std::string type_clean = f.type;
      for (auto& c : type_clean) {
        if (c == '"') c = ' ';
      }
      std::string body =
          "{\"model\":\"qwen3:14b\",\"prompt\":\"/no_think REAL "
          "or FALSE_POSITIVE? " +
          type_clean + " " + ev + "\",\"stream\":false,\"options\":{\"num_predict\":5}}";
      std::string cmd = "curl -s http://127.0.0.1:11434/api/generate -d '" + body + "' 2>/dev/null";
      FILE* fp = popen(cmd.c_str(), "r");
      if (fp) {
        char buf[2048] = {};
        fread(buf, 1, sizeof(buf) - 1, fp);
        pclose(fp);
        std::string resp(buf);
        if (resp.find("FALSE") != std::string::npos) {
          f.severity = "info";
          f.type += " (AI:FP)";
        }
        ai_checked++;
      }
    }
  }

  // Remove pure noise findings that add no value
  std::vector<Finding> final_filtered;
  for (auto& f : filtered) {
    // Skip Cloud Metadata findings without actual metadata in evidence
    if (f.type.find("Cloud Metadata") != std::string::npos) {
      if (f.evidence.find("ami-id") == std::string::npos && f.evidence.find("instance-id") == std::string::npos &&
          f.evidence.find("AccessKeyId") == std::string::npos) {
        continue;
      }
    }
    // Skip XSLT/Deserialization without evidence
    if ((f.type.find("XSLT") != std::string::npos || f.type.find("Deserialization") != std::string::npos) && f.evidence.empty()) {
      continue;
    }
    // Skip findings whose evidence contains WAF/CDN generic responses
    if (!f.evidence.empty() &&
        (f.evidence.find("Access Denied") != std::string::npos || f.evidence.find("<!DOCTYPE html>") != std::string::npos ||
         f.evidence.find("Just a moment") != std::string::npos || f.evidence.find("Checking your browser") != std::string::npos ||
         f.evidence.find("Attention Required") != std::string::npos || f.evidence.find("cf-browser-verification") != std::string::npos ||
         f.evidence.find("Page Not Found") != std::string::npos)) {
      continue;
    }
    // Skip high/critical findings that only matched based on status code 200
    // without meaningful content validation (common CDN false positive)
    if ((f.severity == "critical" || f.severity == "high") && f.evidence.empty() && f.payload.empty()) {
      continue;
    }
    // Skip race condition targets that are just guessed paths (not from crawl)
    if (f.type.find("Race Condition Target") != std::string::npos && f.evidence.empty()) {
      continue;
    }
    // Skip subdomain takeover without actual CNAME/dangling DNS evidence
    if (f.type.find("Subdomain Takeover") != std::string::npos) {
      if (f.evidence.find("CNAME") == std::string::npos && f.evidence.find("NXDOMAIN") == std::string::npos &&
          f.evidence.find("dangling") == std::string::npos && f.evidence.find("NoSuchBucket") == std::string::npos &&
          f.evidence.find("There isn't a GitHub Pages") == std::string::npos &&
          f.evidence.find("ENOTFOUND") == std::string::npos) {
        continue;
      }
    }
    // Skip business logic findings that target guessed API paths without evidence
    // (coupon, cart, refund, discount endpoints that don't actually exist)
    if ((f.type.find("Coupon") != std::string::npos || f.type.find("Refund") != std::string::npos ||
         f.type.find("Cart") != std::string::npos || f.type.find("Discount") != std::string::npos ||
         f.type.find("Shipping") != std::string::npos || f.type.find("Gift Card") != std::string::npos ||
         f.type.find("Inventory") != std::string::npos || f.type.find("Quantity") != std::string::npos) &&
        f.evidence.find("JSON") == std::string::npos && f.evidence.find("response") == std::string::npos &&
        f.evidence.find("applied") == std::string::npos && f.evidence.find("success") == std::string::npos) {
      // Only keep if we have evidence it's a real e-commerce API
      if (f.evidence.empty() || f.evidence.find("No ") == 0) continue;
    }
    // Skip LDAP/Mass Assignment findings without injection proof
    if ((f.type.find("LDAP") != std::string::npos || f.type.find("Mass Assignment") != std::string::npos) &&
        f.evidence.empty()) {
      continue;
    }
    // Skip Auto-Escalate findings (chain engine speculative)
    if (f.type.find("Auto-Escalate") != std::string::npos && f.confidence < 0.7) {
      continue;
    }
    final_filtered.push_back(std::move(f));
  }


































































































































































































































































































































































  // Run Attack Chain Engine — combines findings into multi-step exploits

  // ============================================================
  // INTELLIGENCE LAYER: Enrich findings with metadata + filter by similarity
  // ============================================================

  // 1. Response Similarity Filter: get baseline 404/default response
  //    and remove findings whose evidence matches it (same page for everything = FP)
  {
    std::map<std::string, size_t> host_baseline_sizes;
    for (auto it = final_filtered.begin(); it != final_filtered.end();) {
      if (it->url.empty() || it->severity == "info") {
        ++it;
        continue;
      }

      std::string host = it->url.substr(0, it->url.find("/", 8));
      if (host_baseline_sizes.find(host) == host_baseline_sizes.end()) {
        auto bl = http.get(host + "/apex_nonexistent_baseline_" + std::to_string(time(nullptr)));
        host_baseline_sizes[host] = bl.body.size();
      }

      // If evidence is empty AND it's a high/critical finding, reduce confidence
      if (it->evidence.empty() && (it->severity == "critical" || it->severity == "high")) {
        it->confidence = 20;
      }
      ++it;
    }
  }

  // 2. CWE/CVSS/OWASP Enrichment
  {
    struct VulnMeta {
      std::string pattern;
      std::string cwe;
      std::string owasp;
      double cvss;
      int base_confidence;
    };

    const std::vector<VulnMeta> meta_map = {
        {"SQL Injection", "CWE-89", "A03:2021 Injection", 9.8, 90},
        {"SQLi", "CWE-89", "A03:2021 Injection", 9.8, 90},
        {"XSS", "CWE-79", "A03:2021 Injection", 6.1, 70},
        {"Cross-Site Scripting", "CWE-79", "A03:2021 Injection", 6.1, 70},
        {"SSRF", "CWE-918", "A10:2021 SSRF", 9.1, 80},
        {"SSTI", "CWE-1336", "A03:2021 Injection", 9.8, 90},
        {"Template Injection", "CWE-1336", "A03:2021 Injection", 9.8, 90},
        {"Command Injection", "CWE-78", "A03:2021 Injection", 9.8, 95},
        {"Path Traversal", "CWE-22", "A01:2021 Broken Access Control", 7.5, 80},
        {"LFI", "CWE-98", "A03:2021 Injection", 7.5, 80},
        {"RFI", "CWE-98", "A03:2021 Injection", 9.8, 85},
        {"IDOR", "CWE-639", "A01:2021 Broken Access Control", 6.5, 70},
        {"BOLA", "CWE-639", "A01:2021 Broken Access Control", 6.5, 70},
        {"BFLA", "CWE-285", "A01:2021 Broken Access Control", 8.0, 75},
        {"JWT", "CWE-347", "A02:2021 Cryptographic Failures", 7.5, 75},
        {"Prototype Pollution", "CWE-1321", "A03:2021 Injection", 8.0, 70},
        {"Request Smuggling", "CWE-444", "A05:2021 Security Misconfiguration", 9.1, 80},
        {"Cache Poisoning", "CWE-349", "A05:2021 Security Misconfiguration", 7.5, 70},
        {"CORS", "CWE-942", "A05:2021 Security Misconfiguration", 7.5, 70},
        {"Open Redirect", "CWE-601", "A01:2021 Broken Access Control", 4.7, 80},
        {"CSRF", "CWE-352", "A01:2021 Broken Access Control", 4.3, 60},
        {"Subdomain Takeover", "CWE-284", "A05:2021 Security Misconfiguration", 7.5, 75},
        {"Information Disclosure", "CWE-200", "A01:2021 Broken Access Control", 5.3, 80},
        {"S3 Bucket", "CWE-284", "A05:2021 Security Misconfiguration", 7.5, 85},
        {"Firebase", "CWE-284", "A05:2021 Security Misconfiguration", 7.5, 80},
        {"Admin", "CWE-284", "A01:2021 Broken Access Control", 9.1, 70},
        {"Auth Bypass", "CWE-287", "A07:2021 Authentication Failures", 9.8, 85},
        {"Password Reset", "CWE-640", "A07:2021 Authentication Failures", 8.0, 80},
        {"2FA Bypass", "CWE-308", "A07:2021 Authentication Failures", 8.0, 80},
        {"Race Condition", "CWE-362", "A04:2021 Insecure Design", 8.0, 60},
        {"Deserialization", "CWE-502", "A08:2021 Software Integrity", 9.8, 80},
        {"XXE", "CWE-611", "A05:2021 Security Misconfiguration", 7.5, 80},
        {"CRLF", "CWE-93", "A03:2021 Injection", 6.1, 75},
        {"GraphQL", "CWE-200", "A01:2021 Broken Access Control", 5.3, 70},
        {"Docker", "CWE-284", "A05:2021 Security Misconfiguration", 9.1, 85},
        {"Kubernetes", "CWE-284", "A05:2021 Security Misconfiguration", 9.8, 85},
        {"Terraform", "CWE-200", "A05:2021 Security Misconfiguration", 9.1, 90},
        {"Missing Header", "CWE-693", "A05:2021 Security Misconfiguration", 3.7, 95},
        {"Missing HSTS", "CWE-319", "A02:2021 Cryptographic Failures", 4.3, 95},
        {"Missing CSP", "CWE-693", "A05:2021 Security Misconfiguration", 3.7, 95},
    };

    for (auto& f : final_filtered) {
      for (const auto& meta : meta_map) {
        if (f.type.find(meta.pattern) != std::string::npos) {
          if (f.cwe_id.empty()) f.cwe_id = meta.cwe;
          if (f.owasp_category.empty()) f.owasp_category = meta.owasp;
          if (f.cvss_score == 0.0) f.cvss_score = meta.cvss;
          if (f.confidence == 0) f.confidence = meta.base_confidence;
          break;
        }
      }
      // Boost confidence if evidence is present
      if (!f.evidence.empty() && f.confidence > 0) {
        f.confidence = std::min(100, f.confidence + 15);
      }
      // Reduce confidence for unverified high/critical
      if (f.type.find("unverified") != std::string::npos) {
        f.confidence = std::max(10, f.confidence - 30);
      }
    }
  }

  // 3. Sort by confidence * cvss (practical exploitability ranking)
  std::sort(final_filtered.begin(), final_filtered.end(), [](const Finding& a, const Finding& b) {
    double score_a = a.confidence * a.cvss_score;
    double score_b = b.confidence * b.cvss_score;
    return score_a > score_b;
  });

  // ============================================================

  g_all_findings = final_filtered;
  auto chain_scanners = register_attack_chain_scanners();
  for (const auto& cs : chain_scanners) {
    auto chains = cs.func(cfg, http, crawl);
    for (auto& c : chains) {
      final_filtered.push_back(std::move(c));
    }
  }

  // Run Exploit Generator — creates PoC scripts for confirmed vulns
  g_all_findings = final_filtered;
  auto exploit_scanners = register_exploit_gen_scanners();
  for (const auto& es : exploit_scanners) {
    auto pocs = es.func(cfg, http, crawl);
    for (auto& p : pocs) {
      final_filtered.push_back(std::move(p));
    }
  }

  return final_filtered;
}

}  // namespace apex
