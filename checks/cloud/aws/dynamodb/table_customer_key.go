package dynamodb

import (
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/providers/aws/dynamodb"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/aquasecurity/trivy-policies/pkg/rules"
)

var CheckTableCustomerKey = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0025",
		Provider:    providers.AWSProvider,
		Service:     "dynamodb",
		ShortCode:   "table-customer-key",
		Summary:     "DynamoDB tables should use at rest encryption with a Customer Managed Key",
		Impact:      "Using AWS managed keys does not allow for fine grained control",
		Resolution:  "Enable server side encryption with a customer managed key",
		Explanation: `DynamoDB tables are encrypted by default using AWS managed encryption keys. To increase control of the encryption and control the management of factors like key rotation, use a Customer Managed Key.`,
		Links: []string{
			"https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformTableCustomerKeyGoodExamples,
			BadExamples:         terraformTableCustomerKeyBadExamples,
			Links:               terraformTableCustomerKeyLinks,
			RemediationMarkdown: terraformTableCustomerKeyRemediationMarkdown,
		},
		Severity: severity.Low,
	},
	func(s *state.State) (results scan.Results) {
		for _, table := range s.AWS.DynamoDB.Tables {
			if table.Metadata.IsUnmanaged() {
				continue
			}
			if table.ServerSideEncryption.Enabled.IsFalse() {
				results.Add(
					"Table encryption does not use a customer-managed KMS key.",
					table.ServerSideEncryption.KMSKeyID,
				)
			} else if table.ServerSideEncryption.KMSKeyID.IsEmpty() ||
				table.ServerSideEncryption.KMSKeyID.EqualTo(dynamodb.DefaultKMSKeyID) {
				results.Add(
					"Table encryption explicitly uses the default KMS key.",
					table.ServerSideEncryption.KMSKeyID,
				)
			} else {
				results.AddPassed(&table)
			}
		}
		return
	},
)
