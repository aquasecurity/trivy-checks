package gke

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckEnableIpAliasing = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0049",
		Provider:    providers.GoogleProvider,
		Service:     "gke",
		ShortCode:   "enable-ip-aliasing",
		Summary:     "Clusters should have IP aliasing enabled",
		Impact:      "Nodes need a NAT gateway to access local services",
		Resolution:  "Enable IP aliasing",
		Explanation: `IP aliasing allows the reuse of public IPs internally, removing the need for a NAT gateway.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableIpAliasingGoodExamples,
			BadExamples:         terraformEnableIpAliasingBadExamples,
			Links:               terraformEnableIpAliasingLinks,
			RemediationMarkdown: terraformEnableIpAliasingRemediationMarkdown,
		},
		Severity:   severity.Low,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.Metadata.IsUnmanaged() {
				continue
			}
			if cluster.IPAllocationPolicy.Enabled.IsFalse() {
				results.Add(
					"Cluster has IP aliasing disabled.",
					cluster.IPAllocationPolicy.Enabled,
				)
			} else {
				results.AddPassed(&cluster)
			}

		}
		return
	},
)
