# METADATA
# title: Ensure that logging of long statements is disabled.
# description: |
#   Logging of statements which could contain sensitive data is not advised, therefore this setting should preclude all statements from being logged.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-MIN-DURATION-STATEMENT
# custom:
#   id: AVD-GCP-0021
#   avd_id: AVD-GCP-0021
#   provider: google
#   service: sql
#   severity: LOW
#   short_code: pg-no-min-statement-logging
#   recommended_action: Disable minimum duration statement logging completely
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sql
#             provider: google
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance
#     good_examples: checks/cloud/google/sql/pg_no_min_statement_logging.yaml
#     bad_examples: checks/cloud/google/sql/pg_no_min_statement_logging.yaml
package builtin.google.sql.google0021

import rego.v1

import data.lib.google.database

deny contains res if {
	some instance in input.google.sql.instances
	database.is_postgres(instance)
	instance.settings.flags.logmindurationstatement.value != -1
	res := result.new(
		"Database instance is configured to log statements.",
		instance.settings.flags.logmindurationstatement,
	)
}
