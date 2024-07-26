package elasticache

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckEnableAtRestEncryption = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0045",
		Provider:    providers.AWSProvider,
		Service:     "elasticache",
		ShortCode:   "enable-at-rest-encryption",
		Summary:     "Elasticache Replication Group stores unencrypted data at-rest.",
		Impact:      "At-rest data in the Replication Group could be compromised if accessed.",
		Resolution:  "Enable at-rest encryption for replication group",
		Explanation: `Data stored within an Elasticache replication node should be encrypted to ensure sensitive data is kept private.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/at-rest-encryption.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableAtRestEncryptionGoodExamples,
			BadExamples:         terraformEnableAtRestEncryptionBadExamples,
			Links:               terraformEnableAtRestEncryptionLinks,
			RemediationMarkdown: terraformEnableAtRestEncryptionRemediationMarkdown,
		},
		Severity:   severity.High,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, group := range s.AWS.ElastiCache.ReplicationGroups {
			if group.AtRestEncryptionEnabled.IsFalse() {
				results.Add(
					"Replication group does not have at-rest encryption enabled.",
					group.AtRestEncryptionEnabled,
				)
			} else {
				results.AddPassed(&group)
			}
		}
		return
	},
)
