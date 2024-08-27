package compute

import (
	"github.com/aquasecurity/trivy-checks/internal/cidr"
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckNoPublicEgress = rules.Register(
	scan.Rule{
		AVDID:       "AVD-DIG-0003",
		Provider:    providers.DigitalOceanProvider,
		Service:     "compute",
		ShortCode:   "no-public-egress",
		Summary:     "The firewall has an outbound rule with open access",
		Impact:      "The port is exposed for ingress from the internet",
		Resolution:  "Set a more restrictive cidr range",
		Explanation: `Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.`,
		Links: []string{
			"https://docs.digitalocean.com/products/networking/firewalls/how-to/configure-rules/",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicEgressGoodExamples,
			BadExamples:         terraformNoPublicEgressBadExamples,
			Links:               terraformNoPublicEgressLinks,
			RemediationMarkdown: terraformNoPublicEgressRemediationMarkdown,
		},
		Severity:   severity.Critical,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, firewall := range s.DigitalOcean.Compute.Firewalls {
			var failed bool
			for _, rule := range firewall.OutboundRules {
				for _, address := range rule.DestinationAddresses {
					if cidr.IsPublic(address.Value()) && cidr.CountAddresses(address.Value()) > 1 {
						failed = true
						results.Add(
							"Egress rule allows access to multiple public addresses.",
							address,
						)
					}
				}
			}
			if !failed {
				results.AddPassed(&firewall)
			}
		}
		return
	},
)
