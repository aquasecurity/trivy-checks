package bigquery

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/bigquery"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckNoPublicAccess = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0046",
		Provider:    providers.GoogleProvider,
		Service:     "bigquery",
		ShortCode:   "no-public-access",
		Summary:     "BigQuery datasets should only be accessible within the organisation",
		Impact:      "Exposure of sensitive data to the public iniernet",
		Resolution:  "Configure access permissions with higher granularity",
		Explanation: `Using 'allAuthenticatedUsers' provides any GCP user - even those outside of your organisation - access to your BigQuery dataset.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicAccessGoodExamples,
			BadExamples:         terraformNoPublicAccessBadExamples,
			Links:               terraformNoPublicAccessLinks,
			RemediationMarkdown: terraformNoPublicAccessRemediationMarkdown,
		},
		Severity:   severity.Critical,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, dataset := range s.Google.BigQuery.Datasets {
			for _, grant := range dataset.AccessGrants {
				if grant.SpecialGroup.EqualTo(bigquery.SpecialGroupAllAuthenticatedUsers) {
					results.Add(
						"Dataset grants access to all authenticated GCP users.",
						grant.SpecialGroup,
					)
				} else {
					results.AddPassed(&grant)
				}
			}
		}
		return
	},
)
