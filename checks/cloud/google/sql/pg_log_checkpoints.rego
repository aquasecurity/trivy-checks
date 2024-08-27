# METADATA
# title: Ensure that logging of checkpoints is enabled.
# description: |
#   Logging checkpoints provides useful diagnostic data, which can identify performance issues in an application and potential DoS vectors.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-CHECKPOINTS
# custom:
#   id: AVD-GCP-0025
#   avd_id: AVD-GCP-0025
#   provider: google
#   service: sql
#   severity: MEDIUM
#   short_code: pg-log-checkpoints
#   recommended_action: Enable checkpoints logging.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sql
#             provider: google
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance
#     good_examples: checks/cloud/google/sql/pg_log_checkpoints.tf.go
#     bad_examples: checks/cloud/google/sql/pg_log_checkpoints.tf.go
package builtin.google.sql.google0025

import rego.v1

import data.lib.google.database

deny contains res if {
	some instance in input.google.sql.instances
	database.is_postgres(instance)
	instance.settings.flags.logcheckpoints.value == false
	res := result.new(
		"Database instance is not configured to log checkpoints.",
		instance.settings.flags.logcheckpoints,
	)
}
