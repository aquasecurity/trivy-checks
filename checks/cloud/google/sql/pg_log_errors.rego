# METADATA
# title: Ensure that Postgres errors are logged
# description: |
#   Setting the minimum log severity too high will cause errors not to be logged
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://postgresqlco.nf/doc/en/param/log_min_messages/
#   - https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-MIN-MESSAGES
# custom:
#   id: GCP-0018
#   aliases:
#     - AVD-GCP-0018
#     - pg-log-errors
#   long_id: google-sql-pg-log-errors
#   provider: google
#   service: sql
#   severity: LOW
#   recommended_action: Set the minimum log severity to at least ERROR
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sql
#             provider: google
#   examples: checks/cloud/google/sql/pg_log_errors.yaml
package builtin.google.sql.google0018

import rego.v1

import data.lib.google.database

deny contains res if {
	some instance in input.google.sql.instances
	database.is_postgres(instance)
	instance.settings.flags.logminmessages.value in {"FATAL", "PANIC", "LOG"}
	res := result.new(
		"Database instance is not configured to log errors.",
		instance.settings.flags.logminmessages,
	)
}
