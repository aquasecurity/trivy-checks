# METADATA
# title: Disable local_infile setting in MySQL
# description: |
#   Arbitrary files can be read from the system using LOAD_DATA unless this setting is disabled.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://dev.mysql.com/doc/refman/8.0/en/load-data-local-security.html
# custom:
#   id: AVD-GCP-0026
#   avd_id: AVD-GCP-0026
#   provider: google
#   service: sql
#   severity: HIGH
#   short_code: mysql-no-local-infile
#   recommended_action: Disable the local infile setting
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sql
#             provider: google
#   examples: checks/cloud/google/sql/mysql_no_local_infile.yaml
package builtin.google.sql.google0026

import rego.v1

import data.lib.google.database

deny contains res if {
	some instance in input.google.sql.instances
	database.is_mysql(instance)
	instance.settings.flags.localinfile.value == true
	res := result.new("Database instance has local file read access enabled.", instance.settings.flags.localinfile)
}
