package computing

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckAddDescriptionToSecurityGroupRule = rules.Register(
	scan.Rule{
		AVDID:      "AVD-NIF-0003",
		Aliases:    []string{"nifcloud-computing-add-description-to-security-group-rule"},
		Provider:   providers.NifcloudProvider,
		Service:    "computing",
		ShortCode:  "add-description-to-security-group-rule",
		Summary:    "Missing description for security group rule.",
		Impact:     "Descriptions provide context for the firewall rule reasons",
		Resolution: "Add descriptions for all security groups rules",
		Explanation: `Security group rules should include a description for auditing purposes.

Simplifies auditing, debugging, and managing security groups.`,
		Links: []string{
			"https://pfs.nifcloud.com/help/fw/rule_new.htm",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformAddDescriptionToSecurityGroupRuleGoodExamples,
			BadExamples:         terraformAddDescriptionToSecurityGroupRuleBadExamples,
			Links:               terraformAddDescriptionToSecurityGroupRuleLinks,
			RemediationMarkdown: terraformAddDescriptionToSecurityGroupRuleRemediationMarkdown,
		},
		Severity:   severity.Low,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, group := range s.Nifcloud.Computing.SecurityGroups {
			for _, rule := range append(group.EgressRules, group.IngressRules...) {
				if rule.Description.IsEmpty() {
					results.Add(
						"Security group rule does not have a description.",
						rule.Description,
					)
				} else {
					results.AddPassed(&rule)
				}
			}

		}
		return
	},
)
