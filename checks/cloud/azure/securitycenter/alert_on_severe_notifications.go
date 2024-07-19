package securitycenter

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckAlertOnSevereNotifications = rules.Register(
	scan.Rule{
		AVDID:      "AVD-AZU-0044",
		Provider:   providers.AzureProvider,
		Service:    "security-center",
		ShortCode:  "alert-on-severe-notifications",
		Summary:    "Send notification emails for high severity alerts",
		Impact:     "The ability to react to high severity notifications could be delayed",
		Resolution: " Set alert notifications to be on",
		Explanation: `It is recommended that at least one valid contact is configured for the security center. 
Microsoft will notify the security contact directly in the event of a security incident using email and require alerting to be turned on.`,
		Links: []string{
			"https://azure.microsoft.com/en-us/services/security-center/",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformAlertOnSevereNotificationsGoodExamples,
			BadExamples:         terraformAlertOnSevereNotificationsBadExamples,
			Links:               terraformAlertOnSevereNotificationsLinks,
			RemediationMarkdown: terraformAlertOnSevereNotificationsRemediationMarkdown,
		},
		Severity:   severity.Medium,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, contact := range s.Azure.SecurityCenter.Contacts {
			if contact.Metadata.IsUnmanaged() {
				continue
			}
			if contact.EnableAlertNotifications.IsFalse() {
				results.Add(
					"Security contact has alert notifications disabled.",
					contact.EnableAlertNotifications,
				)
			} else {
				results.AddPassed(&contact)
			}
		}
		return
	},
)
