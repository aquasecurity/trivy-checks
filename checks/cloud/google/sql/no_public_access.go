package sql

import (
	"github.com/aquasecurity/trivy-checks/internal/cidr"
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckNoPublicAccess = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0017",
		Provider:    providers.GoogleProvider,
		Service:     "sql",
		ShortCode:   "no-public-access",
		Summary:     "Ensure that Cloud SQL Database Instances are not publicly exposed",
		Impact:      "Public exposure of sensitive data",
		Resolution:  "Remove public access from database instances",
		Explanation: `Database instances should be configured so that they are not available over the public internet, but to internal compute resources which access them.`,
		Links: []string{
			"https://www.cloudconformity.com/knowledge-base/gcp/CloudSQL/publicly-accessible-cloud-sql-instances.html",
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
		for _, instance := range s.Google.SQL.Instances {
			if instance.Metadata.IsUnmanaged() {
				continue
			}
			if instance.Settings.IPConfiguration.EnableIPv4.IsTrue() {
				results.Add(
					"Database instance is granted a public internet address.",
					instance.Settings.IPConfiguration.EnableIPv4,
				)
			}
			for _, network := range instance.Settings.IPConfiguration.AuthorizedNetworks {
				if cidr.IsPublic(network.CIDR.Value()) {
					results.Add(
						"Database instance allows access from the public internet.",
						network.CIDR,
					)
				} else {
					results.AddPassed(&instance)
				}
			}
		}
		return
	},
)
