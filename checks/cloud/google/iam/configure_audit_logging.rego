# METADATA
# title: IAM Audit Not Properly Configured
# description: |
#   IAM Audit Logging should be configured for all services and the appropriate log types to track changes and accesses.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/google_project_iam#google_project_iam_audit_config
#   - https://cloud.google.com/blog/products/management-tools/best-practices-for-working-with-google-cloud-audit-logging
#   - https://cloud.google.com/logging/docs/audit
# custom:
#   id: GCP-0079
#   aliases:
#     - AVD-GCP-0079
#     - configure-audit-logging
#   long_id: google-iam-configure-audit-logging
#   provider: google
#   service: iam
#   severity: LOW
#   minimum_trivy_version: 0.66.0
#   recommended_action: |
#     Configure IAM Audit Logs for required services and log types. In Terraform, use `google_project_iam_audit_config` to specify the services and log types (ADMIN_READ, DATA_READ, DATA_WRITE) to be audited.
#     Note: DATA_READ and DATA_WRITE audit logs can generate significant volumes and costs for high-traffic applications.
#     Consider implementing exemptions for service accounts and evaluating cost implications before enabling for all services.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: google
#   examples: checks/cloud/google/iam/configure_audit_logging.yaml
package builtin.google.iam.google0079

import rego.v1

deny contains res if {
	project := input.google.iam.projects[_]
	isManaged(project)
	count(project.auditconfigs) == 0

	res := result.new(
		"Project should have audit logging configured for security compliance.",
		project,
	)
}

deny contains res if {
	project := input.google.iam.projects[_]
	audit_config := project.auditconfigs[_]
	isManaged(project)

	audit_config.service.value != "allServices"

	res := result.new(
		"Audit configuration should use 'allServices' to ensure comprehensive coverage across all Google Cloud services.",
		audit_config.service,
	)
}

deny contains res if {
	project := input.google.iam.projects[_]
	audit_config := project.auditconfigs[_]
	isManaged(audit_config)

	required_log_types := {"ADMIN_READ", "DATA_WRITE", "DATA_READ"}
	configured_log_types := {log_config.logtype.value | log_config := audit_config.auditlogconfigs[_]}

	missing_types := required_log_types - configured_log_types
	count(missing_types) > 0

	res := result.new(
		sprintf("Audit configuration is missing required log types: %v", [missing_types]),
		audit_config,
	)
}
