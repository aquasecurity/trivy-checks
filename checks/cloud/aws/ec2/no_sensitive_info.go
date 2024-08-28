package ec2

import (
	"fmt"

	"github.com/aquasecurity/trivy/pkg/iac/severity"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/aquasecurity/trivy-checks/pkg/rules"

	"github.com/aquasecurity/trivy/pkg/iac/providers"

	"github.com/owenrumney/squealer/pkg/squealer"
)

var CheckNoSensitiveInfo = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0122",
		Aliases:     []string{"aws-autoscaling-no-sensitive-info"},
		Provider:    providers.AWSProvider,
		Service:     "ec2",
		ShortCode:   "no-sensitive-info",
		Summary:     "Ensure all data stored in the launch configuration EBS is securely encrypted",
		Impact:      "Sensitive credentials in user data can be leaked",
		Resolution:  "Don't use sensitive data in user data",
		Explanation: `When creating Launch Configurations, user data can be used for the initial configuration of the instance. User data must not contain any sensitive data.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoSensitiveInfoGoodExamples,
			BadExamples:         terraformNoSensitiveInfoBadExamples,
			Links:               terraformNoSensitiveInfoLinks,
			RemediationMarkdown: terraformNoSensitiveInfoRemediationMarkdown,
		},
		Severity:   severity.High,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		scanner := squealer.NewStringScanner()
		for _, launchConfig := range s.AWS.EC2.LaunchConfigurations {
			if result := scanner.Scan(launchConfig.UserData.Value()); result.TransgressionFound {
				results.Add(
					fmt.Sprintf("Sensitive data found in user data: %s", result.Description),
					launchConfig.UserData,
				)
			} else {
				results.AddPassed(&launchConfig)
			}
		}
		return
	},
)
