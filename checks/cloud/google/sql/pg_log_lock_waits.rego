# METADATA
# title: Ensure that logging of lock waits is enabled.
# description: |
#   Lock waits are often an indication of poor performance and often an indicator of a potential denial of service vulnerability, therefore occurrences should be logged for analysis.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-LOCK-WAITS
# custom:
#   id: AVD-GCP-0020
#   avd_id: AVD-GCP-0020
#   provider: google
#   service: sql
#   severity: MEDIUM
#   short_code: pg-log-lock-waits
#   recommended_action: Enable lock wait logging.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sql
#             provider: google
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance
#     good_examples: checks/cloud/google/sql/pg_log_lock_waits.yaml
#     bad_examples: checks/cloud/google/sql/pg_log_lock_waits.yaml
package builtin.google.sql.google0020

import rego.v1

import data.lib.google.database

deny contains res if {
	some instance in input.google.sql.instances
	database.is_postgres(instance)
	instance.settings.flags.loglockwaits.value == false
	res := result.new(
		"Database instance is not configured to log lock waits.",
		instance.settings.flags.loglockwaits,
	)
}
