# METADATA
# title: Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server
# description: |
#   Postgresql can generate logs for successful connections to improve visibility for audit and configuration issue resolution.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/postgresql/concepts-server-logs#configure-logging
# custom:
#   id: AVD-AZU-0019
#   avd_id: AVD-AZU-0019
#   provider: azure
#   service: database
#   severity: MEDIUM
#   short_code: postgres-configuration-log-connections
#   recommended_action: Enable connection logging
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: database
#             provider: azure
#   examples: checks/cloud/azure/database/postgres_configuration_log_connections.yaml
package builtin.azure.database.azure0019

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some server in input.azure.database.postgresqlservers
	isManaged(server)
	not server.config.logconnections.value
	res := result.new(
		"Database server is not configured to log connections.",
		metadata.obj_by_path(server, ["config", "logconnections"]),
	)
}
