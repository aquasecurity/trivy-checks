# METADATA
# title: Contained database authentication should be disabled
# description: |
#   Users with ALTER permissions on users can grant access to a contained database without the knowledge of an administrator
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/contained-database-authentication-server-configuration-option?view=sql-server-ver15
# custom:
#   id: GCP-0023
#   aliases:
#     - AVD-GCP-0023
#     - no-contained-db-auth
#   long_id: google-sql-no-contained-db-auth
#   provider: google
#   service: sql
#   severity: MEDIUM
#   recommended_action: Disable contained database authentication
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sql
#             provider: google
#   examples: checks/cloud/google/sql/no_contained_db_auth.yaml
package builtin.google.sql.google0023

import rego.v1

import data.lib.google.database

deny contains res if {
	some instance in input.google.sql.instances
	database.is_sql_server(instance)
	instance.settings.flags.containeddatabaseauthentication.value == true
	res := result.new(
		"Database instance has contained database authentication enabled.",
		instance.settings.flags.containeddatabaseauthentication,
	)
}
