package rds

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckNoClassicResources = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0081",
		Deprecated: true,
		Provider:   providers.AWSProvider,
		Service:    "rds",
		ShortCode:  "no-classic-resources",
		Summary:    "AWS Classic resource usage.",
		Impact:     "Classic resources are running in a shared environment with other customers",
		Resolution: "Switch to VPC resources",
		Explanation: `AWS Classic resources run in a shared environment with infrastructure owned by other AWS customers. You should run
resources in a VPC instead.`,
		Links: []string{
			"https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-classic-platform.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoClassicResourcesGoodExamples,
			BadExamples:         terraformNoClassicResourcesBadExamples,
			Links:               terraformNoClassicResourcesLinks,
			RemediationMarkdown: terraformNoClassicResourcesRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationNoClassicResourcesGoodExamples,
			BadExamples:         cloudFormationNoClassicResourcesBadExamples,
			Links:               cloudFormationNoClassicResourcesLinks,
			RemediationMarkdown: cloudFormationNoClassicResourcesRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results scan.Results) {
		for _, group := range s.AWS.RDS.Classic.DBSecurityGroups {
			results.Add(
				"Classic resources should not be used.",
				&group,
			)
		}
		return
	},
)
