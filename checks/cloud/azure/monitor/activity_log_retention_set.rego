# METADATA
# title: Ensure the activity retention log is set to at least a year
# description: |
#   The average time to detect a breach is up to 210 days, to ensure that all the information required for an effective investigation is available, the retention period should allow for delayed starts to investigating.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/platform-logs-overview
# custom:
#   id: AVD-AZU-0031
#   avd_id: AVD-AZU-0031
#   provider: azure
#   service: monitor
#   severity: MEDIUM
#   short_code: activity-log-retention-set
#   recommended_action: Set a retention period that will allow for delayed investigation
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: monitor
#             provider: azure
#   examples: checks/cloud/azure/monitor/activity_log_retention_set.yaml
package builtin.azure.monitor.azure0031

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some profile in input.azure.monitor.logprofiles
	isManaged(profile)
	not profile.retentionpolicy.enabled.value
	res := result.new(
		"Profile does not enable the log retention policy.",
		metadata.obj_by_path(profile, ["retentionpolicy", "enabled"]),
	)
}

deny contains res if {
	some profile in input.azure.monitor.logprofiles
	isManaged(profile)
	profile.retentionpolicy.enabled.value
	not is_recommended_retention_policy(profile)
	res := result.new(
		"Profile has a log retention policy of less than 1 year.",
		metadata.obj_by_path(profile, ["retentionpolicy", "days"]),
	)
}

is_recommended_retention_policy(profile) := profile.retentionpolicy.days.value >= 365
