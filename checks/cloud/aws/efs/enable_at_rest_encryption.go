package efs

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckEnableAtRestEncryption = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0037",
		Provider:    providers.AWSProvider,
		Service:     "efs",
		ShortCode:   "enable-at-rest-encryption",
		Summary:     "EFS Encryption has not been enabled",
		Impact:      "Data can be read from the EFS if compromised",
		Resolution:  "Enable encryption for EFS",
		Explanation: `If your organization is subject to corporate or regulatory policies that require encryption of data and metadata at rest, we recommend creating a file system that is encrypted at rest, and mounting your file system using encryption of data in transit.`,
		Links: []string{
			"https://docs.aws.amazon.com/efs/latest/ug/encryption.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableAtRestEncryptionGoodExamples,
			BadExamples:         terraformEnableAtRestEncryptionBadExamples,
			Links:               terraformEnableAtRestEncryptionLinks,
			RemediationMarkdown: terraformEnableAtRestEncryptionRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnableAtRestEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableAtRestEncryptionBadExamples,
			Links:               cloudFormationEnableAtRestEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableAtRestEncryptionRemediationMarkdown,
		},
		Severity:   severity.High,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, fs := range s.AWS.EFS.FileSystems {
			if fs.Encrypted.IsFalse() {
				results.Add(
					"File system is not encrypted.",
					fs.Encrypted,
				)
			} else {
				results.AddPassed(&fs)
			}
		}
		return
	},
)
