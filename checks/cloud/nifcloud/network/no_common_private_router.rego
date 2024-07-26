# METADATA
# title: The router has common private network
# description: |
#   When handling sensitive data between servers, please consider using a private LAN to isolate the private side network from the shared network.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://pfs.nifcloud.com/service/plan.htm
# custom:
#   id: AVD-NIF-0017
#   avd_id: AVD-NIF-0017
#   provider: nifcloud
#   service: network
#   severity: LOW
#   short_code: no-common-private-router
#   recommended_action: Use private LAN
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: network
#             provider: nifcloud
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/router#network_id
#     good_examples: checks/cloud/nifcloud/network/no_common_private_router.tf.go
#     bad_examples: checks/cloud/nifcloud/network/no_common_private_router.tf.go
package builtin.nifcloud.network.nifcloud0017

import rego.v1

deny contains res if {
	some router in input.nifcloud.network.routers
	some ni in router.networkinterfaces
	ni.networkid.value == "net-COMMON_PRIVATE"
	res := result.new("The router has common private network", ni.networkid)
}
