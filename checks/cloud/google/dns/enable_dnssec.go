package dns

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckEnableDnssec = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0013",
		Provider:    providers.GoogleProvider,
		Service:     "dns",
		ShortCode:   "enable-dnssec",
		Summary:     "Cloud DNS should use DNSSEC",
		Impact:      "Unverified DNS responses could lead to man-in-the-middle attacks",
		Resolution:  "Enable DNSSEC",
		Explanation: `DNSSEC authenticates DNS responses, preventing MITM attacks and impersonation.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableDnssecGoodExamples,
			BadExamples:         terraformEnableDnssecBadExamples,
			Links:               terraformEnableDnssecLinks,
			RemediationMarkdown: terraformEnableDnssecRemediationMarkdown,
		},
		Severity:   severity.Medium,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, zone := range s.Google.DNS.ManagedZones {
			if zone.Metadata.IsUnmanaged() || zone.IsPrivate() {
				continue
			}
			if zone.DNSSec.Enabled.IsFalse() {
				results.Add(
					"Managed zone does not have DNSSEC enabled.",
					zone.DNSSec.Enabled,
				)
			} else {
				results.AddPassed(&zone)
			}
		}
		return
	},
)
