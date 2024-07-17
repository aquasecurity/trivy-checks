package compute

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckEnableShieldedVMVTPM = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0041",
		Provider:    providers.GoogleProvider,
		Service:     "compute",
		ShortCode:   "enable-shielded-vm-vtpm",
		Summary:     "Instances should have Shielded VM VTPM enabled",
		Impact:      "Unable to prevent unwanted system state modification",
		Resolution:  "Enable Shielded VM VTPM",
		Explanation: `The virtual TPM provides numerous security measures to your VM.`,
		Links: []string{
			"https://cloud.google.com/blog/products/identity-security/virtual-trusted-platform-module-for-shielded-vms-security-in-plaintext",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableShieldedVmVtpmGoodExamples,
			BadExamples:         terraformEnableShieldedVmVtpmBadExamples,
			Links:               terraformEnableShieldedVmVtpmLinks,
			RemediationMarkdown: terraformEnableShieldedVmVtpmRemediationMarkdown,
		},
		Severity:   severity.Medium,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.Google.Compute.Instances {
			if instance.Metadata.IsUnmanaged() {
				continue
			}
			if instance.ShieldedVM.VTPMEnabled.IsFalse() {
				results.Add(
					"Instance does not have VTPM for shielded VMs enabled.",
					instance.ShieldedVM.VTPMEnabled,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)
