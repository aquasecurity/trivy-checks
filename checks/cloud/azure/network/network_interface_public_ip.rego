# METADATA
# title: Network Interfaces With Public IP
# description: |
#   Avoid assigning public IP addresses to network interfaces unless necessary.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_interface#public_ip_address_id
# custom:
#   id: AZU-0076
#   long_id: azure-network-network-interface-public-ip
#   aliases:
#     - AVD-AZU-0076
#     - network-interface-public-ip
#     - azure-network-network-interface-public-ip
#   provider: azure
#   service: network
#   severity: MEDIUM
#   minimum_trivy_version: 0.68.0
#   recommended_action: Remove public IP addresses from network interfaces unless they are specifically required for internet connectivity.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: network
#             provider: azure
#   examples: checks/cloud/azure/network/network_interface_public_ip.yaml
package builtin.azure.network.azure0076

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some ni in input.azure.network.networkinterfaces
	value.is_true(ni.haspublicip)
	res := result.new(
		"Network interface has a public IP address assigned, which increases attack surface.",
		metadata.obj_by_path(ni, ["haspublicip"]),
	)
}
