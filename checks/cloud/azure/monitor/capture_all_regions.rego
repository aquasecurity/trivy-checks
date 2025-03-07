# METADATA
# title: Ensure activitys are captured for all locations
# description: |
#   Log profiles should capture all regions to ensure that all events are logged
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.microsoft.com/en-us/cli/azure/monitor/log-profiles?view=azure-cli-latest#az_monitor_log_profiles_create-required-parameters
# custom:
#   id: AVD-AZU-0032
#   avd_id: AVD-AZU-0032
#   provider: azure
#   service: monitor
#   severity: MEDIUM
#   short_code: capture-all-regions
#   recommended_action: Enable capture for all locations
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: monitor
#             provider: azure
#   examples: checks/cloud/azure/monitor/capture_all_regions.yaml
package builtin.azure.monitor.azure0032

import rego.v1

deny contains res if {
	some profile in input.azure.monitor.logprofiles
	missing := missing_regions(profile)
	count(missing) > 0
	det := details(missing)
	res := result.new(
		sprintf("Log profile does not log to all regions (%s).", [det]),
		profile,
	)
}

details(missing) := msg if {
	count(missing) < 10
	msg := sprintf("missing: %v", [missing])
} else := sprintf("%d regions are missing", [count(missing)])

missing_regions(profile) := missing if {
	regions := {
	val |
		some region in profile.locations
		val := region.value
	}

	missing := required_regions - regions
}

required_regions := {
	"eastus",
	"eastus2",
	"southcentralus",
	"westus2",
	"westus3",
	"australiaeast",
	"southeastasia",
	"northeurope",
	"swedencentral",
	"uksouth",
	"westeurope",
	"centralus",
	"northcentralus",
	"westus",
	"southafricanorth",
	"centralindia",
	"eastasia",
	"japaneast",
	"jioindiawest",
	"koreacentral",
	"canadacentral",
	"francecentral",
	"germanywestcentral",
	"norwayeast",
	"switzerlandnorth",
	"uaenorth",
	"brazilsouth",
	"centralusstage",
	"eastusstage",
	"eastus2stage",
	"northcentralusstage",
	"southcentralusstage",
	"westusstage",
	"westus2stage",
	"asia",
	"asiapacific",
	"australia",
	"brazil",
	"canada",
	"europe",
	"global",
	"india",
	"japan",
	"uk",
	"unitedstates",
	"eastasiastage",
	"southeastasiastage",
	"centraluseuap",
	"eastus2euap",
	"westcentralus",
	"southafricawest",
	"australiacentral",
	"australiacentral2",
	"australiasoutheast",
	"japanwest",
	"jioindiacentral",
	"koreasouth",
	"southindia",
	"westindia",
	"canadaeast",
	"francesouth",
	"germanynorth",
	"norwaywest",
	"swedensouth",
	"switzerlandwest",
	"ukwest",
	"uaecentral",
	"brazilsoutheast",
}
