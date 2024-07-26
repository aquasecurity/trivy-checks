package elb

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/elb"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckDropInvalidHeaders = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AWS-0052",
		Provider:   providers.AWSProvider,
		Service:    "elb",
		ShortCode:  "drop-invalid-headers",
		Summary:    "Load balancers should drop invalid headers",
		Impact:     "Invalid headers being passed through to the target of the load balance may exploit vulnerabilities",
		Resolution: "Set drop_invalid_header_fields to true",
		Explanation: `Passing unknown or invalid headers through to the target poses a potential risk of compromise. 

By setting drop_invalid_header_fields to true, anything that doe not conform to well known, defined headers will be removed by the load balancer.`,
		Links: []string{
			"https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformDropInvalidHeadersGoodExamples,
			BadExamples:         terraformDropInvalidHeadersBadExamples,
			Links:               terraformDropInvalidHeadersLinks,
			RemediationMarkdown: terraformDropInvalidHeadersRemediationMarkdown,
		},
		Severity:   severity.High,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, lb := range s.AWS.ELB.LoadBalancers {
			if lb.Metadata.IsUnmanaged() || !lb.Type.EqualTo(elb.TypeApplication) || lb.Metadata.IsUnmanaged() {
				continue
			}
			if lb.DropInvalidHeaderFields.IsFalse() {
				results.Add(
					"Application load balancer is not set to drop invalid headers.",
					lb.DropInvalidHeaderFields,
				)
			} else {
				results.AddPassed(&lb)
			}
		}
		return
	},
)
