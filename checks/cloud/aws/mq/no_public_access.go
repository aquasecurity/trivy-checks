package mq

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckNoPublicAccess = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0072",
		Provider:    providers.AWSProvider,
		Service:     "mq",
		ShortCode:   "no-public-access",
		Summary:     "Ensure MQ Broker is not publicly exposed",
		Impact:      "Publicly accessible MQ Broker may be vulnerable to compromise",
		Resolution:  "Disable public access when not required",
		Explanation: `Public access of the MQ broker should be disabled and only allow routes to applications that require access.`,
		Links: []string{
			"https://docs.aws.amazon.com/amazon-mq/latest/developer-guide/using-amazon-mq-securely.html#prefer-brokers-without-public-accessibility",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicAccessGoodExamples,
			BadExamples:         terraformNoPublicAccessBadExamples,
			Links:               terraformNoPublicAccessLinks,
			RemediationMarkdown: terraformNoPublicAccessRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationNoPublicAccessGoodExamples,
			BadExamples:         cloudFormationNoPublicAccessBadExamples,
			Links:               cloudFormationNoPublicAccessLinks,
			RemediationMarkdown: cloudFormationNoPublicAccessRemediationMarkdown,
		},
		Severity:   severity.High,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, broker := range s.AWS.MQ.Brokers {
			if broker.PublicAccess.IsTrue() {
				results.Add(
					"Broker has public access enabled.",
					broker.PublicAccess,
				)
			} else {
				results.AddPassed(&broker)
			}
		}
		return
	},
)
