package gke

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckNodeShieldingEnabled = rules.Register(
	scan.Rule{
		AVDID:      "AVD-GCP-0055",
		Provider:   providers.GoogleProvider,
		Service:    "gke",
		ShortCode:  "node-shielding-enabled",
		Summary:    "Shielded GKE nodes not enabled.",
		Impact:     "Node identity and integrity can't be verified without shielded GKE nodes",
		Resolution: "Enable node shielding",
		Explanation: `CIS GKE Benchmark Recommendation: 6.5.5. Ensure Shielded GKE Nodes are Enabled

Shielded GKE Nodes provide strong, verifiable node identity and integrity to increase the security of GKE nodes and should be enabled on all GKE clusters.`,
		Links: []string{
			"https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#shielded_nodes",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNodeShieldingEnabledGoodExamples,
			BadExamples:         terraformNodeShieldingEnabledBadExamples,
			Links:               terraformNodeShieldingEnabledLinks,
			RemediationMarkdown: terraformNodeShieldingEnabledRemediationMarkdown,
		},
		Severity:   severity.High,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.Metadata.IsUnmanaged() {
				continue
			}
			if cluster.EnableShieldedNodes.IsFalse() {
				results.Add(
					"Cluster has shielded nodes disabled.",
					cluster.EnableShieldedNodes,
				)
			} else {
				results.AddPassed(&cluster)
			}

		}
		return
	},
)
