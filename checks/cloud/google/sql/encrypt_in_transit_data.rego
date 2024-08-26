# METADATA
# title: SSL connections to a SQL database instance should be enforced.
# description: |
#   In-transit data should be encrypted so that if traffic is intercepted data will not be exposed in plaintext to attackers.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://cloud.google.com/sql/docs/mysql/configure-ssl-instance
# custom:
#   id: AVD-GCP-0015
#   avd_id: AVD-GCP-0015
#   provider: google
#   service: sql
#   severity: HIGH
#   short_code: encrypt-in-transit-data
#   recommended_action: Enforce SSL for all connections
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sql
#             provider: google
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/sql_database_instance
#     good_examples: checks/cloud/google/sql/encrypt_in_transit_data.tf.go
#     bad_examples: checks/cloud/google/sql/encrypt_in_transit_data.tf.go
package builtin.google.sql.google0015

import rego.v1

deny contains res if {
	some instance in input.google.sql.instances
	instance.settings.ipconfiguration.requiretls.value == false
	res := result.new(
		"Database instance does not require TLS for all connections.",
		instance.settings.ipconfiguration.requiretls,
	)
}
