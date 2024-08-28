package ec2

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckIMDSAccessRequiresToken = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0028",
		Provider:   providers.AWSProvider,
		Service:    "ec2",
		ShortCode:  "enforce-http-token-imds",
		Summary:    "aws_instance should activate session tokens for Instance Metadata Service.",
		Impact:     "Instance metadata service can be interacted with freely",
		Resolution: "Enable HTTP token requirement for IMDS",
		Explanation: `
IMDS v2 (Instance Metadata Service) introduced session authentication tokens which improve security when talking to IMDS.
By default <code>aws_instance</code> resource sets IMDS session auth tokens to be optional. 
To fully protect IMDS you need to enable session tokens by using <code>metadata_options</code> block and its <code>http_tokens</code> variable set to <code>required</code>.
`,

		Links: []string{
			"https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service",
		},

		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnforceHttpTokenImdsGoodExamples,
			BadExamples:         terraformEnforceHttpTokenImdsBadExamples,
			Links:               terraformEnforceHttpTokenImdsLinks,
			RemediationMarkdown: terraformEnforceHttpTokenImdsRemediationMarkdown,
		},
		Severity:   severity.High,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.AWS.EC2.Instances {
			if !instance.RequiresIMDSToken() && !instance.HasHTTPEndpointDisabled() {
				results.Add(
					"Instance does not require IMDS access to require a token",
					instance.MetadataOptions.HttpTokens,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return results
	},
)
