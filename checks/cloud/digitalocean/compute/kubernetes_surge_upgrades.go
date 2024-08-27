package compute

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckKubernetesSurgeUpgrades = rules.Register(
	scan.Rule{
		AVDID:       "AVD-DIG-0005",
		Provider:    providers.DigitalOceanProvider,
		Service:     "compute",
		ShortCode:   "surge-upgrades-not-enabled",
		Summary:     "The Kubernetes cluster does not enable surge upgrades",
		Impact:      "Upgrades may influence availability of your Kubernetes cluster",
		Resolution:  "Enable surge upgrades in your Kubernetes cluster",
		Explanation: `While upgrading your cluster, workloads will temporarily be moved to new nodes. A small cost will follow, but as a bonus, you won't experience downtime.`,
		Links: []string{
			"https://docs.digitalocean.com/products/kubernetes/how-to/upgrade-cluster/#surge-upgrades",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformKubernetesClusterSurgeUpgradesGoodExamples,
			BadExamples:         terraformKubernetesClusterSurgeUpgradesBadExamples,
			Links:               terraformKubernetesClusterSurgeUpgradeLinks,
			RemediationMarkdown: terraformKubernetesClusterSurgeUpgradesMarkdown,
		},
		Severity:   severity.Medium,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, kc := range s.DigitalOcean.Compute.KubernetesClusters {
			if kc.Metadata.IsUnmanaged() {
				continue
			}
			if kc.SurgeUpgrade.IsFalse() {
				results.Add(
					"Surge upgrades are disabled in your Kubernetes cluster. Please enable this feature.",
					kc.SurgeUpgrade,
				)
			} else {
				results.AddPassed(&kc)
			}
		}
		return
	},
)
