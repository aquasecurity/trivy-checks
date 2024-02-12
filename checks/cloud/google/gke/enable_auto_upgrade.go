package gke

import (
	"github.com/aquasecurity/trivy-policies/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckEnableAutoUpgrade = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0058",
		Provider:    providers.GoogleProvider,
		Service:     "gke",
		ShortCode:   "enable-auto-upgrade",
		Summary:     "Kubernetes should have 'Automatic upgrade' enabled",
		Impact:      "Nodes will need the cluster master version manually updating",
		Resolution:  "Enable automatic upgrades",
		Explanation: `Automatic updates keep nodes updated with the latest cluster master version.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableAutoUpgradeGoodExamples,
			BadExamples:         terraformEnableAutoUpgradeBadExamples,
			Links:               terraformEnableAutoUpgradeLinks,
			RemediationMarkdown: terraformEnableAutoUpgradeRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			for _, nodePool := range cluster.NodePools {
				if nodePool.Management.EnableAutoUpgrade.IsFalse() {
					results.Add(
						"Node pool does not have auto-upgraade enabled.",
						nodePool.Management.EnableAutoUpgrade,
					)
				} else {
					results.AddPassed(&nodePool)
				}

			}
		}
		return
	},
)
