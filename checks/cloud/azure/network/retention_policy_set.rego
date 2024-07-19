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
#   id: AVD-AZU-0049
#   avd_id: AVD-AZU-0049
#   provider: azure
#   service: network
#   severity: LOW
#   short_code: retention-policy-set
#   recommended_action: Ensure flow log retention is turned on with an expiry of >90 days
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: network
#             provider: azure
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_watcher_flow_log#retention_policy
#     good_examples: checks/cloud/azure/network/retention_policy_set.tf.go
#     bad_examples: checks/cloud/azure/network/retention_policy_set.tf.go
package builtin.azure.network.azure0049

import rego.v1

flowlogs := input.azure.network.networkwatcherflowlogs

deny contains res if {
	some flowlog in flowlogs
	isManaged(flowlog)

	not flowlog.retentionpolicy.enabled.value
	res := result.new(
		"Flow log does not enable the log retention policy.",
		object.get(flowlog, ["retentionpolicy", "enabled"], flowlog),
	)
}

deny contains res if {
	some flowlog in flowlogs
	isManaged(flowlog)

	flowlog.retentionpolicy.enabled.value
	flowlog.retentionpolicy.days.value < 90
	res := result.new(
		"Flow log has a log retention policy of less than 90 days.",
		object.get(flowlog, ["retentionpolicy", "days"], flowlog),
	)
}
