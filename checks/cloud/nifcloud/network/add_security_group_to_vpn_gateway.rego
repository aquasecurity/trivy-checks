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
#   aliases:
#     - nifcloud-computing-add-security-group-to-vpn-gateway
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
#   examples: checks/cloud/nifcloud/network/add_security_group_to_vpn_gateway.yaml
package builtin.nifcloud.network.nifcloud0018

import rego.v1

import data.lib.cloud.value

deny contains res if {
	some gateway in input.nifcloud.network.vpngateways
	without_sg(gateway)
	res := result.new("VpnGateway does not have a security group.", gateway.securitygroup)
}

without_sg(gateway) if value.is_empty(gateway.securitygroup)

without_sg(gateway) if not gateway.securitygroup
