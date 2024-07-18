package iam

import (
	"time"

	"github.com/aquasecurity/trivy/pkg/iac/framework"

	"github.com/aquasecurity/trivy/pkg/iac/severity"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/aquasecurity/trivy-checks/pkg/rules"

	"github.com/aquasecurity/trivy/pkg/iac/providers"
)

var CheckRemoveExpiredCertificates = rules.Register(
	scan.Rule{
		AVDID:    "AVD-AWS-0168",
		Provider: providers.AWSProvider,
		Frameworks: map[framework.Framework][]string{
			framework.CIS_AWS_1_4: {"1.19"},
		},
		Service:    "iam",
		ShortCode:  "remove-expired-certificates",
		Summary:    "Delete expired TLS certificates",
		Impact:     "Risk of misconfiguration and damage to credibility",
		Resolution: "Remove expired certificates",
		Explanation: `
Removing expired SSL/TLS certificates eliminates the risk that an invalid certificate will be
deployed accidentally to a resource such as AWS Elastic Load Balancer (ELB), which can
damage the credibility of the application/website behind the ELB. As a best practice, it is
recommended to delete expired certificates.
			`,
		Links: []string{
			"https://console.aws.amazon.com/iam/",
		},
		Severity:   severity.Low,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, certificate := range s.AWS.IAM.ServerCertificates {
			if certificate.Expiration.Before(time.Now()) {
				results.Add("Certificate has expired.", &certificate)
			} else {
				results.AddPassed(&certificate)
			}
		}
		return
	},
)
