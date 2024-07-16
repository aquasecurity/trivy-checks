package dns

import (
	"fmt"

	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckNoRsaSha1 = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0012",
		Provider:    providers.GoogleProvider,
		Service:     "dns",
		ShortCode:   "no-rsa-sha1",
		Summary:     "Zone signing should not use RSA SHA1",
		Impact:      "Less secure encryption algorithm than others available",
		Resolution:  "Use RSA SHA512",
		Explanation: `RSA SHA1 is a weaker algorithm than SHA2-based algorithms such as RSA SHA256/512`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoRsaSha1GoodExamples,
			BadExamples:         terraformNoRsaSha1BadExamples,
			Links:               terraformNoRsaSha1Links,
			RemediationMarkdown: terraformNoRsaSha1RemediationMarkdown,
		},
		Severity:   severity.Medium,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, zone := range s.Google.DNS.ManagedZones {
			if zone.Metadata.IsUnmanaged() {
				continue
			}
			for _, keySpec := range zone.DNSSec.DefaultKeySpecs {

				if keySpec.Algorithm.EqualTo("rsasha1") {
					results.Add(
						fmt.Sprintf("Zone uses %q key type with RSA SHA1 algorithm for signing.", keySpec.KeyType.Value()),
						keySpec.Algorithm,
					)
				}
			}
		}
		return
	},
)
