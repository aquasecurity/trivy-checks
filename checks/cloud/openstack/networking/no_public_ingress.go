package compute

import (
	"github.com/aquasecurity/trivy-checks/internal/cidr"
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckNoPublicIngress = rules.Register(
	scan.Rule{
		AVDID:       "AVD-OPNSTK-0003",
		Provider:    providers.OpenStackProvider,
		Service:     "networking",
		ShortCode:   "no-public-ingress",
		Summary:     "A security group rule allows ingress traffic from multiple public addresses",
		Impact:      "Exposure of infrastructure to the public internet",
		Resolution:  "Employ more restrictive security group rules",
		Explanation: `Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicIngressGoodExamples,
			BadExamples:         terraformNoPublicIngressBadExamples,
			Links:               terraformNoPublicIngressLinks,
			RemediationMarkdown: terraformNoPublicIngressRemediationMarkdown,
		},
		Severity:   severity.Medium,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, group := range s.OpenStack.Networking.SecurityGroups {
			for _, rule := range group.Rules {
				if rule.Metadata.IsUnmanaged() || rule.IsIngress.IsFalse() {
					continue
				}
				if cidr.IsPublic(rule.CIDR.Value()) && cidr.CountAddresses(rule.CIDR.Value()) > 1 {
					results.Add(
						"Security group rule allows ingress from multiple public addresses.",
						rule.CIDR,
					)
				} else {
					results.AddPassed(rule)
				}
			}
		}
		return
	},
)
