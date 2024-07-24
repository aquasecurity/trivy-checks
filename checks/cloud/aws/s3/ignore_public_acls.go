package s3

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckPublicACLsAreIgnored = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0091",
		Provider:   providers.AWSProvider,
		Service:    "s3",
		ShortCode:  "ignore-public-acls",
		Summary:    "S3 Access Block should Ignore Public Acl",
		Impact:     "PUT calls with public ACLs specified can make objects public",
		Resolution: "Enable ignoring the application of public ACLs in PUT calls",
		Explanation: `
S3 buckets should ignore public ACLs on buckets and any objects they contain. By ignoring rather than blocking, PUT calls with public ACLs will still be applied but the ACL will be ignored.
`,
		Links: []string{
			"https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformIgnorePublicAclsGoodExamples,
			BadExamples:         terraformIgnorePublicAclsBadExamples,
			Links:               terraformIgnorePublicAclsLinks,
			RemediationMarkdown: terraformIgnorePublicAclsRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationIgnorePublicAclsGoodExamples,
			BadExamples:         cloudFormationIgnorePublicAclsBadExamples,
			Links:               cloudFormationIgnorePublicAclsLinks,
			RemediationMarkdown: cloudFormationIgnorePublicAclsRemediationMarkdown,
		},
		Severity:   severity.High,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, bucket := range s.AWS.S3.Buckets {
			if bucket.PublicAccessBlock == nil {
				results.Add("No public access block so not ignoring public acls", &bucket)
			} else if bucket.PublicAccessBlock.IgnorePublicACLs.IsFalse() {
				results.Add(
					"Public access block does not ignore public ACLs",
					bucket.PublicAccessBlock.IgnorePublicACLs,
				)
			} else {
				results.AddPassed(&bucket)
			}
		}
		return results
	},
)
