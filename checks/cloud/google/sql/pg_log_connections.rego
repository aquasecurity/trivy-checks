# METADATA
# title: Ensure that logging of connections is enabled.
# description: |
#   Logging connections provides useful diagnostic data such as session length, which can identify performance issues in an application and potential DoS vectors.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-CONNECTIONS
# custom:
#   id: GCP-0016
#   aliases:
#     - AVD-GCP-0016
#     - pg-log-connections
#   long_id: google-sql-pg-log-connections
#   provider: google
#   service: sql
#   severity: MEDIUM
#   recommended_action: Enable connection logging.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sql
#             provider: google
#   examples: checks/cloud/google/sql/pg_log_connections.yaml
package builtin.google.sql.google0016

import rego.v1

import data.lib.google.database

deny contains res if {
	some instance in input.google.sql.instances
	database.is_postgres(instance)
	instance.settings.flags.logconnections.value == false
	res := result.new(
		"Database instance is not configured to log connections.",
		instance.settings.flags.logconnections,
	)
}
