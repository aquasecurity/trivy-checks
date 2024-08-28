package iam

import (
	"github.com/aquasecurity/trivy/pkg/iac/framework"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/severity"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/aquasecurity/trivy-checks/pkg/rules"

	"github.com/aquasecurity/trivy/pkg/iac/providers"
)

var CheckRequireSupportRole = rules.Register(
	scan.Rule{
		AVDID:    "AVD-AWS-0169",
		Provider: providers.AWSProvider,
		Frameworks: map[framework.Framework][]string{
			framework.CIS_AWS_1_4: {"1.17"},
		},
		Service:    "iam",
		ShortCode:  "require-support-role",
		Summary:    "Missing IAM Role to allow authorized users to manage incidents with AWS Support.",
		Impact:     "Incident management is not possible without a support role.",
		Resolution: "Create an IAM role with the necessary permissions to manage incidents with AWS Support.",
		Explanation: `
By implementing least privilege for access control, an IAM Role will require an appropriate
IAM Policy to allow Support Center Access in order to manage Incidents with AWS Support.
			`,
		Links: []string{
			"https://console.aws.amazon.com/iam/",
		},
		Severity:   severity.Low,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {

		for _, role := range s.AWS.IAM.Roles {
			for _, policy := range role.Policies {
				if policy.Builtin.IsTrue() && policy.Name.EqualTo("AWSSupportAccess") {
					results.AddPassed(&role)
					return
				}
			}
		}

		results.Add("Missing IAM support role.", trivyTypes.NewUnmanagedMetadata())
		return results
	},
)
