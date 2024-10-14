# METADATA
# title: Database auditing rentention period should be longer than 90 days
# description: |
#   When Auditing is configured for a SQL database, if the retention period is not set, the retention will be unlimited.
#
#   If the retention period is to be explicitly set, it should be set for no less than 90 days.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/azure-sql/database/auditing-overview
# custom:
#   id: AVD-AZU-0025
#   avd_id: AVD-AZU-0025
#   provider: azure
#   service: database
#   severity: MEDIUM
#   short_code: retention-period-set
#   recommended_action: Set retention periods of database auditing to greater than 90 days
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: database
#             provider: azure
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_database_extended_auditing_policy
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server#retention_in_days
#     good_examples: checks/cloud/azure/database/retention_period_set.yaml
#     bad_examples: checks/cloud/azure/database/retention_period_set.yaml
package builtin.azure.database.azure0025

import rego.v1

import data.lib.cloud.value

deny contains res if {
	some server in input.azure.database.mssqlservers
	some policy in server.extendedauditingpolicies
	value.less_than(policy.retentionindays, 90)
	value.is_not_equal(policy.retentionindays, 0)

	res := result.new(
		"Server has a retention period of less than 90 days.",
		policy.retentionindays,
	)
}
