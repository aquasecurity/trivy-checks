# METADATA
# title: Ensure log profile captures all activities
# description: |
#   Log profiles should capture all categories to ensure that all events are logged
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log
#   - https://docs.microsoft.com/en-us/cli/azure/monitor/log-profiles?view=azure-cli-latest#az_monitor_log_profiles_create-required-parameters
# custom:
#   id: AVD-AZU-0033
#   avd_id: AVD-AZU-0033
#   provider: azure
#   service: monitor
#   severity: MEDIUM
#   short_code: capture-all-activities
#   recommended_action: Configure log profile to capture all activities
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: monitor
#             provider: azure
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_log_profile#categories
#     good_examples: checks/cloud/azure/monitor/capture_all_activities.tf.go
#     bad_examples: checks/cloud/azure/monitor/capture_all_activities.tf.go
package builtin.azure.monitor.azure0033

import rego.v1

required_categories := {"Action", "Write", "Delete"}

deny contains res if {
	some profile in input.azure.monitor.logprofiles
	isManaged(profile)
	missing := missing_required_categories(profile)
	count(missing) > 0
	res := result.new(
		sprintf("Log profile does not require categories: %v", [missing]),
		profile,
	)
}

missing_required_categories(profile) := missing if {
	categories := {
	val |
		some category in profile.categories
		val := category.value
	}

	missing := required_categories - categories
} else := {}
