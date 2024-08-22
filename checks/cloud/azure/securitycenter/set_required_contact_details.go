package securitycenter

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckSetRequiredContactDetails = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AZU-0046",
		Provider:   providers.AzureProvider,
		Service:    "security-center",
		ShortCode:  "set-required-contact-details",
		Summary:    "The required contact details should be set for security center",
		Impact:     "Without a telephone number set, Azure support can't contact",
		Resolution: "Set a telephone number for security center contact",
		Explanation: `It is recommended that at least one valid contact is configured for the security center. 
Microsoft will notify the security contact directly in the event of a security incident and will look to use a telephone number in cases where a prompt response is required.`,
		Links: []string{
			"https://azure.microsoft.com/en-us/services/security-center/",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformSetRequiredContactDetailsGoodExamples,
			BadExamples:         terraformSetRequiredContactDetailsBadExamples,
			Links:               terraformSetRequiredContactDetailsLinks,
			RemediationMarkdown: terraformSetRequiredContactDetailsRemediationMarkdown,
		},
		Severity:   severity.Low,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, contact := range s.Azure.SecurityCenter.Contacts {
			if contact.Metadata.IsUnmanaged() {
				continue
			}
			if contact.Phone.IsEmpty() {
				results.Add(
					"Security contact does not have a phone number listed.",
					contact.Phone,
				)
			} else {
				results.AddPassed(&contact)
			}
		}
		return
	},
)
