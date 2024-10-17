# METADATA
# title: Synapse Workspace should have managed virtual network enabled, the default is disabled.
# description: |
#   Synapse Workspace does not have managed virtual network enabled by default.
#
#   When you create your Azure Synapse workspace, you can choose to associate it to a Microsoft Azure Virtual Network. The Virtual Network associated with your workspace is managed by Azure Synapse. This Virtual Network is called a Managed workspace Virtual Network.
#
#   Managed private endpoints are private endpoints created in a Managed Virtual Network associated with your Azure Synapse workspace. Managed private endpoints establish a private link to Azure resources. You can only use private links in a workspace that has a Managed workspace Virtual Network.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/synapse-analytics/security/synapse-workspace-managed-private-endpoints
#   - https://docs.microsoft.com/en-us/azure/synapse-analytics/security/synapse-workspace-managed-vnet
# custom:
#   id: AVD-AZU-0034
#   avd_id: AVD-AZU-0034
#   provider: azure
#   service: synapse
#   severity: MEDIUM
#   short_code: virtual-network-enabled
#   recommended_action: Set manage virtual network to enabled
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: synapse
#             provider: azure
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/synapse_workspace#managed_virtual_network_enabled
#     good_examples: checks/cloud/azure/synapse/virtual_network_enabled.yaml
#     bad_examples: checks/cloud/azure/synapse/virtual_network_enabled.yaml
package builtin.azure.synapse.azure0034

import rego.v1

deny contains res if {
	some workspace in input.azure.synapse.workspaces
	isManaged(workspace)

	not workspace.enablemanagedvirtualnetwork.value
	res := result.new(
		"Workspace does not have a managed virtual network enabled.",
		object.get(workspace, "enablemanagedvirtualnetwork", workspace),
	)
}
