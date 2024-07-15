package rdb

import (
	"github.com/aquasecurity/trivy-checks/internal/cidr"
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckNoPublicIngressDBSgr = rules.Register(
	scan.Rule{
		AVDID:       "AVD-NIF-0011",
		Aliases:     []string{"nifcloud-rdb-no-public-ingress-db-sgr"},
		Provider:    providers.NifcloudProvider,
		Service:     "rdb",
		ShortCode:   "no-public-ingress-db-sgr",
		Summary:     "An ingress db security group rule allows traffic from /0.",
		Impact:      "Your port exposed to the internet",
		Resolution:  "Set a more restrictive cidr range",
		Explanation: `Opening up ports to the public internet is generally to be avoided. You should restrict access to IP addresses or ranges that explicitly require it where possible.`,
		Links: []string{
			"https://pfs.nifcloud.com/api/rdb/AuthorizeDBSecurityGroupIngress.htm",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoPublicIngressDBSgrGoodExamples,
			BadExamples:         terraformNoPublicIngressDBSgrBadExamples,
			Links:               terraformNoPublicIngressDBSgrLinks,
			RemediationMarkdown: terraformNoPublicIngressDBSgrRemediationMarkdown,
		},
		Severity:   severity.Critical,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, group := range s.Nifcloud.RDB.DBSecurityGroups {
			for _, rule := range group.CIDRs {
				if cidr.IsPublic(rule.Value()) && cidr.CountAddresses(rule.Value()) > 1 {
					results.Add(
						"DB Security group rule allows ingress from public internet.",
						rule,
					)
				} else {
					results.AddPassed(&group)
				}
			}
		}
		return
	},
)
