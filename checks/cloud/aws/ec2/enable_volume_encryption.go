package ec2

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckEnableVolumeEncryption = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0026",
		Aliases:     []string{"aws-ebs-enable-volume-encryption"},
		Provider:    providers.AWSProvider,
		Service:     "ec2",
		ShortCode:   "enable-volume-encryption",
		Summary:     "EBS volumes must be encrypted",
		Impact:      "Unencrypted sensitive data is vulnerable to compromise.",
		Resolution:  "Enable encryption of EBS volumes",
		Explanation: `By enabling encryption on EBS volumes you protect the volume, the disk I/O and any derived snapshots from compromise if intercepted.`,
		Links:       []string{"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html"},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableVolumeEncryptionGoodExamples,
			BadExamples:         terraformEnableVolumeEncryptionBadExamples,
			Links:               terraformEnableVolumeEncryptionLinks,
			RemediationMarkdown: terraformEnableVolumeEncryptionRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnableVolumeEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableVolumeEncryptionBadExamples,
			Links:               cloudFormationEnableVolumeEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableVolumeEncryptionRemediationMarkdown,
		},
		Severity:   severity.High,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, volume := range s.AWS.EC2.Volumes {
			if volume.Metadata.IsUnmanaged() {
				continue
			}
			if volume.Encryption.Enabled.IsFalse() {
				results.Add(
					"EBS volume is not encrypted.",
					volume.Encryption.Enabled,
				)
			} else {
				results.AddPassed(&volume)
			}
		}
		return
	},
)
