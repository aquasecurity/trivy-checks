# METADATA
# title: Network Watcher Flow Disabled
# description: |
#   Without NSG flow logs, network activity is not auditable, hindering incident investigation.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_watcher_flow_log
# custom:
#   id: AZU-0073
#   long_id: azure-network-network-watcher-flow-disabled
#   aliases:
#     - AVD-AZU-0073
#     - network-watcher-flow-disabled
#     - azure-network-watcher-flow-disabled
#   provider: azure
#   service: network
#   severity: MEDIUM
#   minimum_trivy_version: 0.68.0
#   recommended_action: Enable NSG flow logs via Network Watcher and configure a storage account for log export.
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: network
#             provider: azure
#   examples: checks/cloud/azure/network/network_watcher_flow_disabled.yaml
package builtin.azure.network.azure0073

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some flowlog in input.azure.network.networkwatcherflowlogs
	value.is_false(flowlog.enabled)
	res := result.new(
		"Network Watcher flow log is disabled.",
		metadata.obj_by_path(flowlog, ["enabled"]),
	)
}
