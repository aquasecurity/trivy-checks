package sslcertificate

import (
	"time"

	"github.com/aquasecurity/trivy/pkg/iac/severity"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/aquasecurity/trivy-checks/pkg/rules"

	"github.com/aquasecurity/trivy/pkg/iac/providers"
)

var CheckRemoveExpiredCertificates = rules.Register(
	scan.Rule{
		AVDID:      "AVD-NIF-0006",
		Provider:   providers.NifcloudProvider,
		Service:    "ssl-certificate",
		ShortCode:  "remove-expired-certificates",
		Summary:    "Delete expired SSL certificates",
		Impact:     "Risk of misconfiguration and damage to credibility",
		Resolution: "Remove expired certificates",
		Explanation: `
Removing expired SSL/TLS certificates eliminates the risk that an invalid certificate will be
deployed accidentally to a resource such as NIFCLOUD Load Balancer(L4LB), which candamage the 
credibility of the application/website behind the L4LB. As a best practice, it is
recommended to delete expired certificates.
			`,
		Links: []string{
			"https://pfs.nifcloud.com/help/ssl/del.htm",
		},
		Severity:   severity.Low,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, certificate := range s.Nifcloud.SSLCertificate.ServerCertificates {
			if certificate.Expiration.Before(time.Now()) {
				results.Add("Certificate has expired.", &certificate)
			} else {
				results.AddPassed(&certificate)
			}
		}
		return
	},
)
