package monitor

import (
	"fmt"

	"github.com/aquasecurity/trivy/pkg/iac/severity"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/aquasecurity/trivy-checks/pkg/rules"

	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/monitor"
)

var CheckCaptureAllActivities = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AZU-0033",
		Provider:    providers.AzureProvider,
		Service:     "monitor",
		ShortCode:   "capture-all-activities",
		Summary:     "Ensure log profile captures all activities",
		Impact:      "Log profile must capture all activity to be able to ensure that all relevant information possible is available for an investigation",
		Resolution:  "Configure log profile to capture all activities",
		Explanation: `Log profiles should capture all categories to ensure that all events are logged`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/activity-log",
			"https://docs.microsoft.com/en-us/cli/azure/monitor/log-profiles?view=azure-cli-latest#az_monitor_log_profiles_create-required-parameters",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformCaptureAllActivitiesGoodExamples,
			BadExamples:         terraformCaptureAllActivitiesBadExamples,
			Links:               terraformCaptureAllActivitiesLinks,
			RemediationMarkdown: terraformCaptureAllActivitiesRemediationMarkdown,
		},
		Severity:   severity.Medium,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		required := []string{
			"Action", "Write", "Delete",
		}
		for _, profile := range s.Azure.Monitor.LogProfiles {
			if profile.Metadata.IsUnmanaged() {
				continue
			}
			var failed bool
			for _, cat := range required {
				if !hasCategory(profile, cat) {
					failed = true
					results.Add(
						fmt.Sprintf("Log profile does not require the '%s' category.", cat),
						&profile,
					)
				}
			}

			if !failed {
				results.AddPassed(&profile)
			}
		}
		return
	},
)

func hasCategory(profile monitor.LogProfile, cgry string) bool {
	for _, category := range profile.Categories {
		if category.EqualTo(cgry) {
			return true
		}
	}
	return false
}
