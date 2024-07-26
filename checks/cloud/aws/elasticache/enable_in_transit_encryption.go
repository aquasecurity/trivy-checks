package elasticache

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckEnableInTransitEncryption = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0051",
		Provider:    providers.AWSProvider,
		Service:     "elasticache",
		ShortCode:   "enable-in-transit-encryption",
		Summary:     "Elasticache Replication Group uses unencrypted traffic.",
		Impact:      "In transit data in the Replication Group could be read if intercepted",
		Resolution:  "Enable in transit encryption for replication group",
		Explanation: `Traffic flowing between Elasticache replication nodes should be encrypted to ensure sensitive data is kept private.`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/in-transit-encryption.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableInTransitEncryptionGoodExamples,
			BadExamples:         terraformEnableInTransitEncryptionBadExamples,
			Links:               terraformEnableInTransitEncryptionLinks,
			RemediationMarkdown: terraformEnableInTransitEncryptionRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnableInTransitEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableInTransitEncryptionBadExamples,
			Links:               cloudFormationEnableInTransitEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableInTransitEncryptionRemediationMarkdown,
		},
		Severity:   severity.High,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, group := range s.AWS.ElastiCache.ReplicationGroups {
			if group.TransitEncryptionEnabled.IsFalse() {
				results.Add(
					"Replication group does not have transit encryption enabled.",
					group.TransitEncryptionEnabled,
				)
			} else {
				results.AddPassed(&group)
			}
		}
		return
	},
)
