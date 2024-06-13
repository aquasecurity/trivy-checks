package athena

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/athena"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckEnableAtRestEncryption = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0006",
		Provider:    providers.AWSProvider,
		Service:     "athena",
		ShortCode:   "enable-at-rest-encryption",
		Summary:     "Athena databases and workgroup configurations are created unencrypted at rest by default, they should be encrypted",
		Impact:      "Data can be read if the Athena Database is compromised",
		Resolution:  "Enable encryption at rest for Athena databases and workgroup configurations",
		Explanation: `Athena databases and workspace result sets should be encrypted at rests. These databases and query sets are generally derived from data in S3 buckets and should have the same level of at rest protection.`,
		Links: []string{
			"https://docs.aws.amazon.com/athena/latest/ug/encryption.html",
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
		for _, workgroup := range s.AWS.Athena.Workgroups {
			if workgroup.Metadata.IsUnmanaged() {
				continue
			}
			if workgroup.Encryption.Type.EqualTo(athena.EncryptionTypeNone) {
				results.Add(
					"Workgroup does not have encryption configured.",
					workgroup.Encryption.Type,
				)
			} else {
				results.AddPassed(&workgroup)
			}
		}
		for _, database := range s.AWS.Athena.Databases {
			if database.Metadata.IsUnmanaged() {
				continue
			}
			if database.Encryption.Type.EqualTo(athena.EncryptionTypeNone) {
				results.Add(
					"Database does not have encryption configured.",
					database.Encryption.Type,
				)
			} else {
				results.AddPassed(&database)
			}
		}
		return
	},
)
