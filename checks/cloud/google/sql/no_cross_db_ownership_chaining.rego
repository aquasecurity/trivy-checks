# METADATA
# title: Cross-database ownership chaining should be disabled
# description: |
#   Cross-database ownership chaining, also known as cross-database chaining, is a security feature of SQL Server that allows users of databases access to other databases besides the one they are currently using.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/cross-db-ownership-chaining-server-configuration-option?view=sql-server-ver15
# custom:
#   id: AVD-GCP-0019
#   avd_id: AVD-GCP-0019
#   provider: google
#   service: sql
#   severity: MEDIUM
#   short_code: no-cross-db-ownership-chaining
#   recommended_action: Disable cross database ownership chaining
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sql
#             provider: google
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance
#     good_examples: checks/cloud/google/sql/no_cross_db_ownership_chaining.yaml
#     bad_examples: checks/cloud/google/sql/no_cross_db_ownership_chaining.yaml
package builtin.google.sql.google0019

import rego.v1

import data.lib.google.database

deny contains res if {
	some instance in input.google.sql.instances
	database.is_sql_server(instance)
	instance.settings.flags.crossdbownershipchaining.value == true
	res := result.new(
		"Database instance has cross database ownership chaining enabled.",
		instance.settings.flags.crossdbownershipchaining,
	)
}
