package msk

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckEnableAtRestEncryption = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0179",
		Provider:    providers.AWSProvider,
		Service:     "msk",
		ShortCode:   "enable-at-rest-encryption",
		Summary:     "A MSK cluster allows unencrypted data at rest.",
		Impact:      "Intercepted data can be read at rest",
		Resolution:  "Enable at rest encryption",
		Explanation: `Encryption should be forced for Kafka clusters, including at rest. This ensures sensitive data is kept private.`,
		Links: []string{
			"https://docs.aws.amazon.com/msk/latest/developerguide/msk-encryption.html",
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
		for _, cluster := range s.AWS.MSK.Clusters {
			if cluster.EncryptionAtRest.Enabled.IsFalse() {
				results.Add("The cluster is not encrypted at rest.", cluster.EncryptionAtRest.Enabled)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)
