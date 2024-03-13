package acm

import (
	"time"

	"github.com/aquasecurity/trivy-policies/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var ACMAcmCertificateExpiry = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0420",
		Provider:    providers.AWSProvider,
		Service:     "acm",
		ShortCode:   "acm-certificate-expiry",
		Summary:     "Detect upcoming expiration of ACM certificates",
		Impact:      "Expired certificates lead to browser warnings and can affect website trust.",
		Resolution:  "Renew certificates before they expire and ensure the domain's email/DNS validation is working.",
		Explanation: `Certificates that have expired will trigger warnings in all major browsers. AWS will attempt to automatically renew the certificate but may be unable to do so if email or DNS validation cannot be confirmed.`,
		Links: []string{
			"https://docs.aws.amazon.com/acm/latest/userguide/managed-renewal.html",
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, cert := range s.AWS.ACM.Certificates {
			if cert.NotAfter.Value().IsZero() {
				results.Add(
					"ACM certificate does not have an expiration date configured",
					cert.NotAfter,
				)
				continue
			}

			difference := int(time.Until(cert.NotAfter.Value()).Hours() / 24)
			expiryPass := 45
			expiryWarn := 30

			if difference > expiryPass {
				results.AddPassed(&cert)
			} else if difference > expiryWarn {
				results.Add(
					"ACM certificate is close to expiry",
					&cert,
				)
			} else {
				results.Add(
					"ACM certificate is critically close to or has expired",
					&cert,
				)
			}
		}
		return results
	},
)
