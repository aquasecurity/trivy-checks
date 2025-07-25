# METADATA
# title: Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database Server
# description: |
#   Postgresql can generate logs for checkpoints to improve visibility for audit and configuration issue resolution.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/postgresql/concepts-server-logs#configure-logging
# custom:
#   id: AZU-0024
#   aliases:
#     - AVD-AZU-0024
#     - postgres-configuration-log-checkpoints
#   long_id: azure-database-postgres-configuration-log-checkpoints
#   provider: azure
#   service: database
#   severity: MEDIUM
#   recommended_action: Enable checkpoint logging
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: database
#             provider: azure
#   examples: checks/cloud/azure/database/postgres_configuration_log_checkpoints.yaml
package builtin.azure.database.azure0024

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some server in input.azure.database.postgresqlservers
	isManaged(server)
	not server.config.logcheckpoints.value
	res := result.new(
		"Database server is not configured to log checkpoints.",
		metadata.obj_by_path(server, ["config", "logcheckpoints"]),
	)
}
