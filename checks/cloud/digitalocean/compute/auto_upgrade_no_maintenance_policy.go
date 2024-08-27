package compute

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckAutoUpgrade = rules.Register(
	scan.Rule{
		AVDID:       "AVD-DIG-0008",
		Provider:    providers.DigitalOceanProvider,
		Service:     "compute",
		ShortCode:   "kubernetes-auto-upgrades-not-enabled",
		Summary:     "Kubernetes clusters should be auto-upgraded to ensure that they always contain the latest security patches.",
		Impact:      "Not running the latest security patches on your Kubernetes cluster can make it a target for penetration.",
		Resolution:  "Set maintenance policy deterministically when auto upgrades are enabled",
		Explanation: ``,
		Links: []string{
			"https://docs.digitalocean.com/products/kubernetes/resources/best-practices/",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformKubernetesClusterAutoUpgradeGoodExamples,
			BadExamples:         terraformKubernetesClusterAutoUpgradeBadExamples,
			Links:               terraformKubernetesClusterAutoUpgradeLinks,
			RemediationMarkdown: terraformKubernetesAutoUpgradeMarkdown,
		},
		Severity:   severity.Critical,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, kc := range s.DigitalOcean.Compute.KubernetesClusters {
			if kc.Metadata.IsUnmanaged() {
				continue
			}
			if kc.AutoUpgrade.IsFalse() {
				results.Add(
					"Kubernetes Cluster does not enable auto upgrades enabled",
					kc.AutoUpgrade,
				)
			} else {
				results.AddPassed(&kc)
			}
		}
		return
	},
)
