package network

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckAddSecurityGroupToRouter = rules.Register(
	scan.Rule{
		AVDID:       "AVD-NIF-0016",
		Aliases:     []string{"nifcloud-computing-add-security-group-to-router"},
		Provider:    providers.NifcloudProvider,
		Service:     "network",
		ShortCode:   "add-security-group-to-router",
		Summary:     "Missing security group for router.",
		Impact:      "A security group controls the traffic that is allowed to reach and leave the resources that it is associated with.",
		Resolution:  "Add security group for all routers",
		Explanation: "Need to add a security group to your router.",
		Links: []string{
			"https://pfs.nifcloud.com/help/router/change.htm",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformAddSecurityGroupToRouterGoodExamples,
			BadExamples:         terraformAddSecurityGroupToRouterBadExamples,
			Links:               terraformAddSecurityGroupToRouterLinks,
			RemediationMarkdown: terraformAddSecurityGroupToRouterRemediationMarkdown,
		},
		Severity:   severity.Critical,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, router := range s.Nifcloud.Network.Routers {
			if router.Metadata.IsUnmanaged() {
				continue
			}
			if router.SecurityGroup.IsEmpty() {
				results.Add(
					"Router does not have a securiy group.",
					router.SecurityGroup,
				)
			} else {
				results.AddPassed(&router)
			}
		}
		return
	},
)
