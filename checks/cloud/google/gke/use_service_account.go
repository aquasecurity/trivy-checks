package gke

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckUseServiceAccount = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0050",
		Provider:    providers.GoogleProvider,
		Service:     "gke",
		ShortCode:   "use-service-account",
		Summary:     "Checks for service account defined for GKE nodes",
		Impact:      "Service accounts with wide permissions can increase the risk of compromise",
		Resolution:  "Use limited permissions for service accounts to be effective",
		Explanation: `You should create and use a minimally privileged service account to run your GKE cluster instead of using the Compute Engine default service account.`,
		Links: []string{
			"https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#use_least_privilege_sa",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformUseServiceAccountGoodExamples,
			BadExamples:         terraformUseServiceAccountBadExamples,
			Links:               terraformUseServiceAccountLinks,
			RemediationMarkdown: terraformUseServiceAccountRemediationMarkdown,
		},
		Severity:   severity.Medium,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.Metadata.IsManaged() {
				if cluster.RemoveDefaultNodePool.IsFalse() {
					if cluster.NodeConfig.ServiceAccount.IsEmpty() {
						results.Add(
							"Cluster does not override the default service account.",
							cluster.NodeConfig.ServiceAccount,
						)
					}
				} else {
					results.AddPassed(&cluster)
				}
			}
			for _, pool := range cluster.NodePools {
				if pool.NodeConfig.ServiceAccount.IsEmpty() {
					results.Add(
						"Node pool does not override the default service account.",
						pool.NodeConfig.ServiceAccount,
					)
				} else {
					results.AddPassed(&pool)
				}
			}
		}
		return
	},
)
