# METADATA
# title: Auditing should be enabled on Azure SQL Databases
# description: |
#   Auditing helps you maintain regulatory compliance, understand database activity, and gain insight into discrepancies and anomalies that could indicate business concerns or suspected security violations.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/azure-sql/database/auditing-overview
# custom:
#   id: AVD-AZU-0027
#   avd_id: AVD-AZU-0027
#   provider: azure
#   service: database
#   severity: MEDIUM
#   short_code: enable-audit
#   recommended_action: Enable auditing on Azure SQL databases
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: database
#             provider: azure
#   examples: checks/cloud/azure/database/enable_audit.yaml
package builtin.azure.database.azure0027

import rego.v1

deny contains res if {
	some server in input.azure.database.mssqlservers
	isManaged(server)
	not policies_is_configured(server)
	res := result.new(
		"Server does not have an extended audit policy configured.",
		server,
	)
}

policies_is_configured(server) := count(server.extendedauditingpolicies) > 0
