# METADATA
# title: Retention policy for flow logs should be enabled and set to greater than 90 days
# description: |
#   Flow logs are the source of truth for all network activity in your cloud environment.
#
#   To enable analysis in security event that was detected late, you need to have the logs available.
#
#   Setting an retention policy will help ensure as much information is available for review.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-monitoring-overview
# custom:
#   id: AZU-0049
#   aliases:
#     - AVD-AZU-0049
#     - retention-policy-set
#   long_id: azure-network-retention-policy-set
#   provider: azure
#   service: network
#   severity: LOW
#   recommended_action: Ensure flow log retention is turned on with an expiry of >90 days
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: network
#             provider: azure
#   examples: checks/cloud/azure/network/retention_policy_set.yaml
package builtin.azure.network.azure0049

import rego.v1

import data.lib.cloud.metadata

import data.lib.cloud.value

flowlogs := input.azure.network.networkwatcherflowlogs

deny contains res if {
	some flowlog in flowlogs
	isManaged(flowlog)

	not flowlog.retentionpolicy.enabled.value
	res := result.new(
		"Flow log does not enable the log retention policy.",
		metadata.obj_by_path(flowlog, ["retentionpolicy", "enabled"]),
	)
}

deny contains res if {
	some flowlog in flowlogs
	isManaged(flowlog)

	flowlog.retentionpolicy.enabled.value
	value.less_than(flowlog.retentionpolicy.days, 90)
	res := result.new(
		"Flow log has a log retention policy of less than 90 days.",
		metadata.obj_by_path(flowlog, ["retentionpolicy", "days"]),
	)
}
