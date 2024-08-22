package compute

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckEnableDiskEncryption = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AZU-0038",
		Provider:    providers.AzureProvider,
		Service:     "compute",
		ShortCode:   "enable-disk-encryption",
		Summary:     "Enable disk encryption on managed disk",
		Impact:      "Data could be read if compromised",
		Resolution:  "Enable encryption on managed disks",
		Explanation: `Manage disks should be encrypted at rest. When specifying the <code>encryption_settings</code> block, the enabled attribute should be set to <code>true</code>.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/virtual-machines/linux/disk-encryption",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableDiskEncryptionGoodExamples,
			BadExamples:         terraformEnableDiskEncryptionBadExamples,
			Links:               terraformEnableDiskEncryptionLinks,
			RemediationMarkdown: terraformEnableDiskEncryptionRemediationMarkdown,
		},
		Severity:   severity.High,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, disk := range s.Azure.Compute.ManagedDisks {
			if disk.Metadata.IsUnmanaged() {
				continue
			}
			if disk.Encryption.Enabled.IsFalse() {
				results.Add(
					"Managed disk is not encrypted.",
					disk.Encryption.Enabled,
				)
			} else {
				results.AddPassed(&disk)
			}
		}
		return
	},
)
