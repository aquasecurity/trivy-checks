package computing

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckAddDescriptionToSecurityGroup = rules.Register(
	scan.Rule{
		AVDID:      "AVD-NIF-0002",
		Aliases:    []string{"nifcloud-computing-add-description-to-security-group"},
		Provider:   providers.NifcloudProvider,
		Service:    "computing",
		ShortCode:  "add-description-to-security-group",
		Summary:    "Missing description for security group.",
		Impact:     "Descriptions provide context for the firewall rule reasons",
		Resolution: "Add descriptions for all security groups",
		Explanation: `Security groups should include a description for auditing purposes.

Simplifies auditing, debugging, and managing security groups.`,
		Links: []string{
			"https://pfs.nifcloud.com/help/fw/change.htm",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformAddDescriptionToSecurityGroupGoodExamples,
			BadExamples:         terraformAddDescriptionToSecurityGroupBadExamples,
			Links:               terraformAddDescriptionToSecurityGroupLinks,
			RemediationMarkdown: terraformAddDescriptionToSecurityGroupRemediationMarkdown,
		},
		Severity:   severity.Low,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, group := range s.Nifcloud.Computing.SecurityGroups {
			if group.Metadata.IsUnmanaged() {
				continue
			}
			if group.Description.IsEmpty() {
				results.Add(
					"Security group does not have a description.",
					group.Description,
				)
			} else if group.Description.EqualTo("Managed by Terraform") {
				results.Add(
					"Security group explicitly uses the default description.",
					group.Description,
				)
			} else {
				results.AddPassed(&group)
			}
		}
		return
	},
)
