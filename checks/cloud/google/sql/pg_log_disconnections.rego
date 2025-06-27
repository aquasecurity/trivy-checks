# METADATA
# title: Ensure that logging of disconnections is enabled.
# description: |
#   Logging disconnections provides useful diagnostic data such as session length, which can identify performance issues in an application and potential DoS vectors.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-DISCONNECTIONS
# custom:
#   id: GCP-0022
#   aliases:
#     - AVD-GCP-0022
#     - pg-log-disconnections
#   long_id: google-sql-pg-log-disconnections
#   provider: google
#   service: sql
#   severity: MEDIUM
#   recommended_action: Enable disconnection logging.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sql
#             provider: google
#   examples: checks/cloud/google/sql/pg_log_disconnections.yaml
package builtin.google.sql.google0022

import rego.v1

import data.lib.google.database

deny contains res if {
	some instance in input.google.sql.instances
	database.is_postgres(instance)
	instance.settings.flags.logdisconnections.value == false
	res := result.new(
		"Database instance is not configured to log disconnections.",
		instance.settings.flags.logdisconnections,
	)
}
