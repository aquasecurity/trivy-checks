package ssm

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

var AvoidLeaksViaHTTP = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0134",
		Provider:    providers.AWSProvider,
		Service:     "ssm",
		ShortCode:   "avoid-leaks-via-http",
		Summary:     "Secrets should not be exfiltrated using Terraform HTTP data blocks",
		Impact:      "Secrets could be exposed outside of the organisation.",
		Resolution:  "Remove this potential exfiltration HTTP request.",
		Explanation: `The data.http block can be used to send secret data outside of the organisation.`,
		Links: []string{
			"https://sprocketfox.io/xssfox/2022/02/09/terraformsupply/",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformAvoidLeaksViaHTTPGoodExamples,
			BadExamples:         terraformAvoidLeaksViaHTTPBadExamples,
			Links:               terraformAvoidLeaksViaHTTPLinks,
			RemediationMarkdown: terraformAvoidLeaksViaHTTPRemediationMarkdown,
		},
		CustomChecks: scan.CustomChecks{
			Terraform: &scan.TerraformCustomCheck{
				RequiredTypes:  []string{"data"},
				RequiredLabels: []string{"http"},
				Check: func(block *terraform.Block, module *terraform.Module) (results scan.Results) {
					attr := block.GetAttribute("url")
					if attr.IsNil() {
						return
					}
					for _, ref := range attr.AllReferences() {
						if ref.BlockType().Name() == "resource" && ref.TypeLabel() == "aws_ssm_parameter" {
							results.Add("Potential exfiltration of secret value detected", block)
						}
					}
					return
				},
			},
		},
		Severity:   severity.Critical,
		Deprecated: true,
	},
	nil,
)
