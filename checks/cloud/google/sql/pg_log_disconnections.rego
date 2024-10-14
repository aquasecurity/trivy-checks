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
#   id: AVD-GCP-0022
#   avd_id: AVD-GCP-0022
#   provider: google
#   service: sql
#   severity: MEDIUM
#   short_code: pg-log-disconnections
#   recommended_action: Enable disconnection logging.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sql
#             provider: google
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance
#     good_examples: checks/cloud/google/sql/pg_log_disconnections.yaml
#     bad_examples: checks/cloud/google/sql/pg_log_disconnections.yaml
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
