package rdb

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckNoCommonPrivateDBInstance = rules.Register(
	scan.Rule{
		AVDID:       "AVD-NIF-0010",
		Aliases:     []string{"nifcloud-rdb-no-common-private-db-instance"},
		Provider:    providers.NifcloudProvider,
		Service:     "rdb",
		ShortCode:   "no-common-private-db-instance",
		Summary:     "The db instance has common private network",
		Impact:      "The common private network is shared with other users",
		Resolution:  "Use private LAN",
		Explanation: `When handling sensitive data between servers, please consider using a private LAN to isolate the private side network from the shared network.`,
		Links: []string{
			"https://pfs.nifcloud.com/service/plan.htm",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoCommonPrivateDBInstanceGoodExamples,
			BadExamples:         terraformNoCommonPrivateDBInstanceBadExamples,
			Links:               terraformNoCommonPrivateDBInstanceLinks,
			RemediationMarkdown: terraformNoCommonPrivateDBInstanceRemediationMarkdown,
		},
		Severity:   severity.Low,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.Nifcloud.RDB.DBInstances {
			if instance.NetworkID.EqualTo("net-COMMON_PRIVATE") {
				results.Add(
					"The db instance has common private network",
					instance.NetworkID,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)
