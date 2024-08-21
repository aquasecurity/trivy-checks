package ec2

import (
	"github.com/aquasecurity/trivy-checks/internal/cidr"
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckNoPublicEgressSgr = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0104",
		Aliases:     []string{"aws-vpc-no-public-egress-sgr"},
		Provider:    providers.AWSProvider,
		Service:     "ec2",
		ShortCode:   "no-public-egress-sgr",
		Summary:     "An egress security group rule allows traffic to /0.",
		Impact:      "Your port is egressing data to the internet",
		Resolution:  "Set a more restrictive cidr range",
		Explanation: `Opening up ports to connect out to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that are explicitly required where possible.`,
		Links: []string{
			"https://docs.aws.amazon.com/whitepapers/latest/building-scalable-secure-multi-vpc-network-infrastructure/centralized-egress-to-internet.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicEgressSgrGoodExamples,
			BadExamples:         terraformNoPublicEgressSgrBadExamples,
			Links:               terraformNoPublicEgressSgrLinks,
			RemediationMarkdown: terraformNoPublicEgressSgrRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationNoPublicEgressSgrGoodExamples,
			BadExamples:         cloudFormationNoPublicEgressSgrBadExamples,
			Links:               cloudFormationNoPublicEgressSgrLinks,
			RemediationMarkdown: cloudFormationNoPublicEgressSgrRemediationMarkdown,
		},
		Severity:   severity.Critical,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, group := range s.AWS.EC2.SecurityGroups {
			for _, rule := range group.EgressRules {
				var fail bool
				for _, block := range rule.CIDRs {
					if cidr.IsPublic(block.Value()) && cidr.CountAddresses(block.Value()) > 1 {
						fail = true
						results.Add(
							"Security group rule allows egress to multiple public internet addresses.",
							block,
						)
					}
				}
				if !fail {
					results.AddPassed(&rule)
				}
			}
		}
		return
	},
)
