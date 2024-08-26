package rds

import (
	"fmt"

	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/rds"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy-checks/pkg/rules"
)

var CheckPerformanceInsightsEncryptionCustomerKey = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0078",
		Provider:   providers.AWSProvider,
		Service:    "rds",
		ShortCode:  "performance-insights-encryption-customer-key",
		Summary:    "Performance Insights encryption should use Customer Managed Keys",
		Impact:     "Using AWS managed keys does not allow for fine grained control",
		Resolution: "Use Customer Managed Keys to encrypt Performance Insights data",
		Explanation: `Amazon RDS uses the AWS managed key for your new DB instance. For complete control over KMS keys, including establishing and maintaining their key policies, IAM policies, and grants, enabling and disabling them, and rotating their cryptographic material, use a customer managed keys.

The encryption key specified in ` + "`" + `performance_insights_kms_key_id` + "`" + ` references a KMS ARN`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_PerfInsights.access-control.html#USER_PerfInsights.access-control.cmk-policy",
			"https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-mgmt",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformPerformanceInsightsEncryptionCustomerKeyGoodExamples,
			BadExamples:         terraformPerformanceInsightsEncryptionCustomerKeyBadExamples,
			Links:               terraformPerformanceInsightsEncryptionCustomerKeyLinks,
			RemediationMarkdown: terraformPerformanceInsightsEncryptionCustomerKeyRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationPerformanceInsightsEncryptionCustomerKeyGoodExamples,
			BadExamples:         cloudFormationPerformanceInsightsEncryptionCustomerKeyBadExamples,
			Links:               cloudFormationPerformanceInsightsEncryptionCustomerKeyLinks,
			RemediationMarkdown: cloudFormationPerformanceInsightsEncryptionCustomerKeyRemediationMarkdown,
		},
		Severity:   severity.Low,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {

		checkCMK := func(entity string, instance rds.Instance) {
			if instance.Metadata.IsUnmanaged() || instance.PerformanceInsights.Enabled.IsFalse() {
				return
			}

			if instance.PerformanceInsights.KMSKeyID.IsEmpty() {
				results.Add(
					fmt.Sprintf("%s Perfomance Insights enctyption does not use a customer-managed KMS key.", entity),
					instance.PerformanceInsights.KMSKeyID,
				)
			} else {
				results.AddPassed(&instance)
			}
		}

		for _, cluster := range s.AWS.RDS.Clusters {
			for _, instance := range cluster.Instances {
				checkCMK("Cluster instance", instance.Instance)
			}
		}
		for _, instance := range s.AWS.RDS.Instances {
			checkCMK("Instance", instance)
		}

		return
	},
)
