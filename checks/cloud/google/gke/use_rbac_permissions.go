package gke

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckUseRbacPermissions = rules.Register(
	scan.Rule{
		AVDID:      "AVD-GCP-0062",
		Provider:   providers.GoogleProvider,
		Service:    "gke",
		ShortCode:  "use-rbac-permissions",
		Summary:    "Legacy ABAC permissions are enabled.",
		Impact:     "ABAC permissions are less secure than RBAC permissions",
		Resolution: "Switch to using RBAC permissions",
		Explanation: `You should disable Attribute-Based Access Control (ABAC), and instead use Role-Based Access Control (RBAC) in GKE.

RBAC has significant security advantages and is now stable in Kubernetes, so it’s time to disable ABAC.`,
		Links: []string{
			"https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster#leave_abac_disabled_default_for_110",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformUseRbacPermissionsGoodExamples,
			BadExamples:         terraformUseRbacPermissionsBadExamples,
			Links:               terraformUseRbacPermissionsLinks,
			RemediationMarkdown: terraformUseRbacPermissionsRemediationMarkdown,
		},
		Severity:   severity.High,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.Google.GKE.Clusters {
			if cluster.Metadata.IsUnmanaged() {
				continue
			}
			if cluster.EnableLegacyABAC.IsTrue() {
				results.Add(
					"Cluster has legacy ABAC enabled.",
					cluster.EnableLegacyABAC,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
