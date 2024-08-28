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
#   id: AVD-GCP-0018
#   avd_id: AVD-GCP-0018
#   provider: google
#   service: sql
#   severity: LOW
#   short_code: pg-log-errors
#   recommended_action: Set the minimum log severity to at least ERROR
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sql
#             provider: google
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance
#     good_examples: checks/cloud/google/sql/pg_log_errors.tf.go
#     bad_examples: checks/cloud/google/sql/pg_log_errors.tf.go
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
