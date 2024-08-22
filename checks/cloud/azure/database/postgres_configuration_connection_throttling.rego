# METADATA
# title: Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database Server
# description: |
#   Postgresql can generate logs for connection throttling to improve visibility for audit and configuration issue resolution.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/postgresql/concepts-server-logs#configure-logging
# custom:
#   id: AVD-AZU-0021
#   avd_id: AVD-AZU-0021
#   provider: azure
#   service: database
#   severity: MEDIUM
#   short_code: postgres-configuration-connection-throttling
#   recommended_action: Enable connection throttling logging
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: database
#             provider: azure
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_configuration
#     good_examples: checks/cloud/azure/database/postgres_configuration_connection_throttling.tf.go
#     bad_examples: checks/cloud/azure/database/postgres_configuration_connection_throttling.tf.go
package builtin.azure.database.azure0021

import rego.v1

deny contains res if {
	some server in input.azure.database.postgresqlservers
	isManaged(server)

	not server.config.connectionthrottling.value
	res := result.new(
		"Database server is not configured to throttle connections.",
		object.get(server, ["config", "connectionthrottling"], server),
	)
}
