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
#   id: AVD-AZU-0073
#   avd_id: AVD-AZU-0073
#   aliases:
#     - azure-network-watcher-flow-disabled
#   provider: azure
#   service: network
#   severity: MEDIUM
#   minimum_trivy_version: 0.68.0
#   short_code: network-watcher-flow-disabled
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

flowlogs := input.azure.network.networkwatcherflowlogs

deny contains res if {
	some flowlog in flowlogs
	not flowlog.enabled.value
	res := result.new(
		"Network Watcher flow log is disabled.",
		metadata.obj_by_path(flowlog, ["enabled"]),
	)
}
