package documentdb

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckEncryptionCustomerKey = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0022",
		Provider:    providers.AWSProvider,
		Service:     "documentdb",
		ShortCode:   "encryption-customer-key",
		Summary:     "DocumentDB encryption should use Customer Managed Keys",
		Impact:      "Using AWS managed keys does not allow for fine grained control",
		Resolution:  "Enable encryption using customer managed keys",
		Explanation: `Encryption using AWS keys provides protection for your DocumentDB underlying storage. To increase control of the encryption and manage factors like rotation use customer managed keys.`,
		Links:       []string{"https://docs.aws.amazon.com/documentdb/latest/developerguide/security.encryption.ssl.public-key.html"},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEncryptionCustomerKeyGoodExamples,
			BadExamples:         terraformEncryptionCustomerKeyBadExamples,
			Links:               terraformEncryptionCustomerKeyLinks,
			RemediationMarkdown: terraformEncryptionCustomerKeyRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEncryptionCustomerKeyGoodExamples,
			BadExamples:         cloudFormationEncryptionCustomerKeyBadExamples,
			Links:               cloudFormationEncryptionCustomerKeyLinks,
			RemediationMarkdown: cloudFormationEncryptionCustomerKeyRemediationMarkdown,
		},
		Severity:   severity.Low,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.AWS.DocumentDB.Clusters {
			if cluster.Metadata.IsManaged() && cluster.KMSKeyID.IsEmpty() {
				results.Add(
					"Cluster encryption does not use a customer-managed KMS key.",
					cluster.KMSKeyID,
				)
			} else {
				results.AddPassed(&cluster)
			}
			for _, instance := range cluster.Instances {
				if instance.Metadata.IsUnmanaged() {
					continue
				}
				if instance.KMSKeyID.IsEmpty() {
					results.Add(
						"Instance encryption does not use a customer-managed KMS key.",
						instance.KMSKeyID,
					)
				} else {
					results.AddPassed(&cluster)
				}

			}
		}
		return
	},
)
