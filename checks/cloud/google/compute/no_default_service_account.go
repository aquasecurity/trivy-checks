package compute

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckNoDefaultServiceAccount = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0044",
		Provider:    providers.GoogleProvider,
		Service:     "compute",
		ShortCode:   "no-default-service-account",
		Summary:     "Instances should not use the default service account",
		Impact:      "Instance has full access to the project",
		Resolution:  "Remove use of default service account",
		Explanation: `The default service account has full project access. Instances should instead be assigned the minimal access they need.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoDefaultServiceAccountGoodExamples,
			BadExamples:         terraformNoDefaultServiceAccountBadExamples,
			Links:               terraformNoDefaultServiceAccountLinks,
			RemediationMarkdown: terraformNoDefaultServiceAccountRemediationMarkdown,
		},
		Severity:   severity.Critical,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.Google.Compute.Instances {
			if instance.Metadata.IsUnmanaged() {
				continue
			}
			if instance.ServiceAccount.IsDefault.IsTrue() {
				results.Add(
					"Instance uses the default service account.",
					instance.ServiceAccount.Email,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)
