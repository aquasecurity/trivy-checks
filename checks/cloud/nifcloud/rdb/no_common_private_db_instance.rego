# METADATA
# title: The db instance has common private network
# description: |
#   When handling sensitive data between servers, please consider using a private LAN to isolate the private side network from the shared network.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://pfs.nifcloud.com/service/plan.htm
# custom:
#   id: AVD-NIF-0010
#   avd_id: AVD-NIF-0010
#   aliases:
#     - nifcloud-rdb-no-common-private-db-instance
#   provider: nifcloud
#   service: rdb
#   severity: LOW
#   short_code: no-common-private-db-instance
#   recommended_action: Use private LAN
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: rdb
#             provider: nifcloud
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/db_instance#network_id
#     good_examples: checks/cloud/nifcloud/rdb/no_common_private_db_instance.yaml
#     bad_examples: checks/cloud/nifcloud/rdb/no_common_private_db_instance.yaml
package builtin.nifcloud.rdb.nifcloud0010

import rego.v1

deny contains res if {
	some db in input.nifcloud.rdb.dbinstances
	db.networkid.value == "net-COMMON_PRIVATE"
	res := result.new("The db instance has common private network.", db.networkid)
}
