# METADATA
# title: Ensure that Cloud SQL Database Instances are not publicly exposed
# description: |
#   Database instances should be configured so that they are not available over the public internet, but to internal compute resources which access them.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://www.cloudconformity.com/knowledge-base/gcp/CloudSQL/publicly-accessible-cloud-sql-instances.html
# custom:
#   id: GCP-0017
#   aliases:
#     - AVD-GCP-0017
#     - no-public-access
#   long_id: google-sql-no-public-access
#   provider: google
#   service: sql
#   severity: HIGH
#   recommended_action: Remove public access from database instances
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: sql
#             provider: google
#   examples: checks/cloud/google/sql/no_public_access.yaml
package builtin.google.sql.google0017

import rego.v1

deny contains res if {
	some instance in input.google.sql.instances
	instance.settings.ipconfiguration.enableipv4.value == true
	res := result.new(
		"Database instance is granted a public internet address.",
		instance.settings.ipconfiguration.enableipv4,
	)
}

deny contains res if {
	some instance in input.google.sql.instances
	some network in instance.settings.ipconfiguration.authorizednetworks
	cidr.is_public(network.cidr.value)
	res := result.new(
		"Database instance allows access from the public internet.",
		network.cidr,
	)
}
