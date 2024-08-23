package compute

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckDisablePasswordAuthentication = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AZU-0039",
		Provider:    providers.AzureProvider,
		Service:     "compute",
		ShortCode:   "disable-password-authentication",
		Summary:     "Password authentication should be disabled on Azure virtual machines",
		Impact:      "Using password authentication is less secure that ssh keys may result in compromised servers",
		Resolution:  "Use ssh authentication for virtual machines",
		Explanation: `Access to virtual machines should be authenticated using SSH keys. Removing the option of password authentication enforces more secure methods while removing the risks inherent with passwords.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformDisablePasswordAuthenticationGoodExamples,
			BadExamples:         terraformDisablePasswordAuthenticationBadExamples,
			Links:               terraformDisablePasswordAuthenticationLinks,
			RemediationMarkdown: terraformDisablePasswordAuthenticationRemediationMarkdown,
		},
		Severity:   severity.High,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, vm := range s.Azure.Compute.LinuxVirtualMachines {
			if vm.Metadata.IsUnmanaged() {
				continue
			}
			if vm.OSProfileLinuxConfig.DisablePasswordAuthentication.IsFalse() {
				results.Add(
					"Linux virtual machine allows password authentication.",
					vm.OSProfileLinuxConfig.DisablePasswordAuthentication,
				)
			} else {
				results.AddPassed(&vm)
			}
		}
		return
	},
)
