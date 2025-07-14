# METADATA
# title: The elb has common private network
# description: |
#   When handling sensitive data between servers, please consider using a private LAN to isolate the private side network from the shared network.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://pfs.nifcloud.com/service/plan.htm
# custom:
#   id: NIF-0019
#   aliases:
#     - AVD-NIF-0019
#     - nifcloud-network-no-common-private-elb
#     - no-common-private-elb
#   long_id: nifcloud-network-no-common-private-elb
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
#   examples: checks/cloud/nifcloud/network/no_common_private_elb.yaml
package builtin.nifcloud.network.nifcloud0019

import rego.v1

deny contains res if {
	some elb in input.nifcloud.network.elasticloadbalancers
	some ni in elb.networkinterfaces
	ni.networkid.value == "net-COMMON_PRIVATE"
	res := result.new("The elb has common private network", ni.networkid)
}
