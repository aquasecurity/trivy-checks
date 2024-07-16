package storage

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckNoPublicAccess = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0001",
		Provider:    providers.GoogleProvider,
		Service:     "storage",
		ShortCode:   "no-public-access",
		Summary:     "Ensure that Cloud Storage bucket is not anonymously or publicly accessible.",
		Impact:      "Public exposure of sensitive data.",
		Resolution:  "Restrict public access to the bucket.",
		Explanation: `Using 'allUsers' or 'allAuthenticatedUsers' as members in an IAM member/binding causes data to be exposed outside of the organisation.`,
		Links: []string{
			"https://jbrojbrojbro.medium.com/you-make-the-rules-with-authentication-controls-for-cloud-storage-53c32543747b",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicAccessGoodExamples,
			BadExamples:         terraformNoPublicAccessBadExamples,
			Links:               terraformNoPublicAccessLinks,
			RemediationMarkdown: terraformNoPublicAccessRemediationMarkdown,
		},
		Severity:   severity.High,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, bucket := range s.Google.Storage.Buckets {
			for _, binding := range bucket.Bindings {
				for _, member := range binding.Members {
					if googleIAMMemberIsExternal(member.Value()) {
						results.Add(
							"Bucket allows public access.",
							member,
						)
					} else {
						results.AddPassed(member)
					}
				}
			}
			for _, member := range bucket.Members {
				if googleIAMMemberIsExternal(member.Member.Value()) {
					results.Add(
						"Bucket allows public access.",
						member.Member,
					)
				} else {
					results.AddPassed(member.Member)
				}
			}
		}
		return
	},
)

func googleIAMMemberIsExternal(member string) bool {
	return member == "allUsers" || member == "allAuthenticatedUsers"
}
