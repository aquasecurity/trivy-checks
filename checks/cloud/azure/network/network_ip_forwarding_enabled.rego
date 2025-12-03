# METADATA
# title: Network Interfaces IP Forwarding Enabled
# description: |
#   IP forwarding should be disabled on network interfaces unless specifically required.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_interface#enable_ip_forwarding
# custom:
#   id: AVD-AZU-0075
#   avd_id: AVD-AZU-0075
#   aliases:
#     - azure-network-network-ip-forwarding-enabled
#   provider: azure
#   service: network
#   severity: MEDIUM
#   minimum_trivy_version: 0.68.0
#   short_code: network-ip-forwarding-enabled
#   recommended_action: Disable IP forwarding on network interfaces unless specifically required for routing purposes.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: network
#             provider: azure
#   examples: checks/cloud/azure/network/network_ip_forwarding_enabled.yaml
package builtin.azure.network.azure0075

import rego.v1

import data.lib.cloud.metadata

networkinterfaces := input.azure.network.networkinterfaces

deny contains res if {
	some ni in networkinterfaces
	value.is_true(ni.enableipforwarding)
	res := result.new(
		"Network interface has IP forwarding enabled, which may pose a security risk.",
		metadata.obj_by_path(ni, ["enableipforwarding"]),
	)
}
