# METADATA
# title: A database resource is marked as publicly accessible.
# description: |
#   Database resources should not publicly available. You should limit all access to the minimum that is required for your application to function.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://pfs.nifcloud.com/guide/rdb/server_new.htm
# custom:
#   id: AVD-NIF-0008
#   avd_id: AVD-NIF-0008
#   provider: nifcloud
#   service: rdb
#   severity: CRITICAL
#   short_code: no-public-db-access
#   recommended_action: Set the database to not be publicly accessible
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: rdb
#             provider: nifcloud
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/db_instance#publicly_accessible
#     good_examples: checks/cloud/nifcloud/rdb/no_public_db_access.tf.go
#     bad_examples: checks/cloud/nifcloud/rdb/no_public_db_access.tf.go
package builtin.nifcloud.rdb.nifcloud0008

import rego.v1

deny contains res if {
	some db in input.nifcloud.rdb.dbinstances
	db.publicaccess.value == true
	res := result.new("Instance is exposed publicly.", db.publicaccess)
}
