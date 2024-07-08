package ec2

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckNoPublicIpSubnet = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0164",
		Aliases:     []string{"aws-subnet-no-public-ip"},
		Provider:    providers.AWSProvider,
		Service:     "ec2",
		ShortCode:   "no-public-ip-subnet",
		Summary:     "Instances in a subnet should not receive a public IP address by default.",
		Impact:      "The instance is publicly accessible",
		Resolution:  "Set the instance to not be publicly accessible",
		Explanation: `You should limit the provision of public IP addresses for resources. Resources should not be exposed on the public internet, but should have access limited to consumers required for the function of your application.`,
		Links: []string{
			"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html#concepts-public-addresses",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicIpSubnetGoodExamples,
			BadExamples:         terraformNoPublicIpSubnetBadExamples,
			Links:               terraformNoPublicIpSubnetLinks,
			RemediationMarkdown: terraformNoPublicIpSubnetRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationNoPublicIpSubnetGoodExamples,
			BadExamples:         cloudFormationNoPublicIpSubnetBadExamples,
			Links:               cloudFormationNoPublicIpSubnetLinks,
			RemediationMarkdown: cloudFormationNoPublicIpSubnetRemediationMarkdown,
		},
		Severity:   severity.High,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, subnet := range s.AWS.EC2.Subnets {
			if subnet.MapPublicIpOnLaunch.IsTrue() {
				results.Add(
					"Subnet associates public IP address.",
					subnet.MapPublicIpOnLaunch,
				)
			} else {
				results.AddPassed(&subnet)
			}
		}
		return
	},
)
