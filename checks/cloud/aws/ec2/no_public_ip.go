package ec2

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckNoPublicIp = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0009",
		Aliases:     []string{"aws-autoscaling-no-public-ip"},
		Provider:    providers.AWSProvider,
		Service:     "ec2",
		ShortCode:   "no-public-ip",
		Summary:     "Launch configuration should not have a public IP address.",
		Impact:      "The instance or configuration is publicly accessible",
		Resolution:  "Set the instance to not be publicly accessible",
		Explanation: `You should limit the provision of public IP addresses for resources. Resources should not be exposed on the public internet, but should have access limited to consumers required for the function of your application.`,
		Links: []string{
			"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-instance-addressing.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicIpGoodExamples,
			BadExamples:         terraformNoPublicIpBadExamples,
			Links:               terraformNoPublicIpLinks,
			RemediationMarkdown: terraformNoPublicIpRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationNoPublicIpGoodExamples,
			BadExamples:         cloudFormationNoPublicIpBadExamples,
			Links:               cloudFormationNoPublicIpLinks,
			RemediationMarkdown: cloudFormationNoPublicIpRemediationMarkdown,
		},
		Severity:   severity.High,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, launchConfig := range s.AWS.EC2.LaunchConfigurations {
			if launchConfig.AssociatePublicIP.IsTrue() {
				results.Add(
					"Launch configuration associates public IP address.",
					launchConfig.AssociatePublicIP,
				)
			} else {
				results.AddPassed(&launchConfig)
			}
		}
		return
	},
)
