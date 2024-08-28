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
		AVDID:      "AVD-GCP-0035",
		Provider:   providers.GoogleProvider,
		Service:    "compute",
		ShortCode:  "no-public-egress",
		Summary:    "An outbound firewall rule allows traffic to /0.",
		Impact:     "The port is exposed for egress to the internet",
		Resolution: "Set a more restrictive cidr range",
		Explanation: `Network security rules should not use very broad subnets.

Where possible, segments should be broken into smaller subnets and avoid using the <code>/0</code> subnet.`,
		Links: []string{
			"https://cloud.google.com/vpc/docs/using-firewalls",
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
		for _, network := range s.Google.Compute.Networks {
			if network.Firewall == nil {
				continue
			}
			for _, rule := range network.Firewall.EgressRules {
				if !rule.IsAllow.IsTrue() {
					continue
				}
				if rule.Enforced.IsFalse() {
					continue
				}
				for _, destination := range rule.DestinationRanges {
					if cidr.IsPublic(destination.Value()) && cidr.CountAddresses(destination.Value()) > 1 {
						results.Add(
							"Firewall rule allows egress traffic to multiple addresses on the public internet.",
							destination,
						)
					} else {
						results.AddPassed(destination)
					}
				}
			}
		}
		return
	},
)
