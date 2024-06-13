package cloudtrail

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var EncryptionCustomerManagedKey = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0015",
		Provider:    providers.AWSProvider,
		Service:     "cloudtrail",
		ShortCode:   "encryption-customer-managed-key",
		Summary:     "CloudTrail should use Customer managed keys to encrypt the logs",
		Impact:      "Using AWS managed keys does not allow for fine grained control",
		Resolution:  "Use Customer managed key",
		Explanation: `Using Customer managed keys provides comprehensive control over cryptographic keys, enabling management of policies, permissions, and rotation, thus enhancing security and compliance measures for sensitive data and systems.`,
		Links: []string{
			"https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html",
			"https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-mgmt",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEncryptionCustomerManagedKeyGoodExamples,
			BadExamples:         terraformEncryptionCustomerManagedKeyBadExamples,
			Links:               terraformEncryptionCustomerManagedKeyLinks,
			RemediationMarkdown: ``,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEncryptionCustomerManagedKeyGoodExamples,
			BadExamples:         cloudFormationEncryptionCustomerManagedKeyBadExamples,
			Links:               cloudFormationEncryptionCustomerManagedKeyLinks,
			RemediationMarkdown: ``,
		},
		Severity:   severity.High,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, trail := range s.AWS.CloudTrail.Trails {
			if trail.KMSKeyID.IsEmpty() {
				results.Add(
					"CloudTrail does not use a customer managed key to encrypt the logs.",
					trail.KMSKeyID,
				)
			} else {
				results.AddPassed(&trail)
			}
		}
		return
	},
)
