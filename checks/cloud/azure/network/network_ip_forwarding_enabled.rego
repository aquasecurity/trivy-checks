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
#   id: AZU-0075
#   long_id: azure-network-network-ip-forwarding-enabled
#   aliases:
#     - AVD-AZU-0075
#     - network-ip-forwarding-enabled
#     - azure-network-network-ip-forwarding-enabled
#   provider: azure
#   service: network
#   severity: MEDIUM
#   minimum_trivy_version: 0.68.0
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
import data.lib.cloud.value

deny contains res if {
	some ni in input.azure.network.networkinterfaces
	value.is_true(ni.enableipforwarding)
	res := result.new(
		"Network interface has IP forwarding enabled, which may pose a security risk.",
		metadata.obj_by_path(ni, ["enableipforwarding"]),
	)
}
