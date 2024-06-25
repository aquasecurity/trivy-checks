package accessanalyzer

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

var CheckEnableAccessAnalyzer = rules.Register(
	scan.Rule{
		AVDID:     "AVD-AWS-0175",
		Provider:  providers.AWSProvider,
		Service:   "accessanalyzer",
		ShortCode: "enable-access-analyzer",
		Frameworks: map[framework.Framework][]string{
			framework.CIS_AWS_1_4: {"1.20"},
		},
		Summary:    "Enable IAM Access analyzer for IAM policies about all resources in each region.",
		Impact:     "Reduced visibility of externally shared resources.",
		Resolution: "Enable IAM Access analyzer across all regions.",
		Explanation: `
AWS IAM Access Analyzer helps you identify the resources in your organization and
accounts, such as Amazon S3 buckets or IAM roles, that are shared with an external entity.
This lets you identify unintended access to your resources and data. Access Analyzer
identifies resources that are shared with external principals by using logic-based reasoning
to analyze the resource-based policies in your AWS environment. IAM Access Analyzer
continuously monitors all policies for S3 bucket, IAM roles, KMS(Key Management Service)
keys, AWS Lambda functions, and Amazon SQS(Simple Queue Service) queues.
`,
		Links: []string{
			"https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html",
		},
		Severity:   severity.Low,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		var enabled bool
		for _, analyzer := range s.AWS.AccessAnalyzer.Analyzers {
			if analyzer.Active.IsTrue() {
				enabled = true
				break
			}
		}
		if !enabled {
			results.Add(
				"Access Analyzer is not enabled.",
				trivyTypes.NewUnmanagedMetadata(),
			)
		} else {
			results.AddPassed(trivyTypes.NewUnmanagedMetadata())
		}
		return
	},
)
