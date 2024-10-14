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
#   id: AVD-NIF-0019
#   avd_id: AVD-NIF-0019
#   aliases:
#     - nifcloud-network-no-common-private-elb
#   provider: nifcloud
#   service: network
#   severity: LOW
#   short_code: no-common-private-elb
#   recommended_action: Use private LAN
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: network
#             provider: nifcloud
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/elb#network_id
#     good_examples: checks/cloud/nifcloud/network/no_common_private_elb.yaml
#     bad_examples: checks/cloud/nifcloud/network/no_common_private_elb.yaml
package builtin.nifcloud.network.nifcloud0019

import rego.v1

deny contains res if {
	some elb in input.nifcloud.network.elasticloadbalancers
	some ni in elb.networkinterfaces
	ni.networkid.value == "net-COMMON_PRIVATE"
	res := result.new("The elb has common private network", ni.networkid)
}
