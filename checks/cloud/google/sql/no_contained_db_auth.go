package sql

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/sql"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckNoContainedDbAuth = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0023",
		Provider:    providers.GoogleProvider,
		Service:     "sql",
		ShortCode:   "no-contained-db-auth",
		Summary:     "Contained database authentication should be disabled",
		Impact:      "Access can be granted without knowledge of the database administrator",
		Resolution:  "Disable contained database authentication",
		Explanation: `Users with ALTER permissions on users can grant access to a contained database without the knowledge of an administrator`,
		Links: []string{
			"https://docs.microsoft.com/en-us/sql/database-engine/configure-windows/contained-database-authentication-server-configuration-option?view=sql-server-ver15",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoContainedDbAuthGoodExamples,
			BadExamples:         terraformNoContainedDbAuthBadExamples,
			Links:               terraformNoContainedDbAuthLinks,
			RemediationMarkdown: terraformNoContainedDbAuthRemediationMarkdown,
		},
		Severity:   severity.Medium,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.Google.SQL.Instances {
			if instance.Metadata.IsUnmanaged() {
				continue
			}
			if instance.DatabaseFamily() != sql.DatabaseFamilySQLServer {
				continue
			}
			if instance.Settings.Flags.ContainedDatabaseAuthentication.IsTrue() {
				results.Add(
					"Database instance has contained database authentication enabled.",
					instance.Settings.Flags.ContainedDatabaseAuthentication,
				)
			} else {
				results.AddPassed(&instance)
			}

		}
		return
	},
)
