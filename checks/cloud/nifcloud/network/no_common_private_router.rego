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
#   id: NIF-0017
#   aliases:
#     - AVD-NIF-0017
#     - nifcloud-network-no-common-private-router
#     - no-common-private-router
#   long_id: nifcloud-network-no-common-private-router
#   provider: nifcloud
#   service: network
#   severity: LOW
#   recommended_action: Use private LAN
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: network
#             provider: nifcloud
#   examples: checks/cloud/nifcloud/network/no_common_private_router.yaml
package builtin.nifcloud.network.nifcloud0017

import rego.v1

deny contains res if {
	some router in input.nifcloud.network.routers
	some ni in router.networkinterfaces
	ni.networkid.value == "net-COMMON_PRIVATE"
	res := result.new("The router has common private network", ni.networkid)
}
