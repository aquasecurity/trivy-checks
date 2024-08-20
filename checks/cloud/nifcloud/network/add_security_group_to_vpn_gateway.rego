# METADATA
# title: Missing security group for vpnGateway.
# description: |
#   Need to add a security group to your vpnGateway.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://pfs.nifcloud.com/help/vpngw/change.htm
# custom:
#   id: AVD-NIF-0018
#   avd_id: AVD-NIF-0018
#   provider: nifcloud
#   service: network
#   severity: CRITICAL
#   short_code: add-security-group-to-vpn-gateway
#   recommended_action: Add security group for all vpnGateways
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: network
#             provider: nifcloud
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/vpn_gateway#security_group
#     good_examples: checks/cloud/nifcloud/network/add_security_group_to_vpn_gateway.tf.go
#     bad_examples: checks/cloud/nifcloud/network/add_security_group_to_vpn_gateway.tf.go
package builtin.nifcloud.network.nifcloud0018

import rego.v1

deny contains res if {
	some gateway in input.nifcloud.network.vpngateways
	gateway.securitygroup.value == ""
	res := result.new("VpnGateway does not have a securiy group.", gateway.securitygroup)
}
