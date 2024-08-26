package sql

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/sql"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckPgLogConnections = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0016",
		Provider:    providers.GoogleProvider,
		Service:     "sql",
		ShortCode:   "pg-log-connections",
		Summary:     "Ensure that logging of connections is enabled.",
		Impact:      "Insufficient diagnostic data.",
		Resolution:  "Enable connection logging.",
		Explanation: `Logging connections provides useful diagnostic data such as session length, which can identify performance issues in an application and potential DoS vectors.`,
		Links: []string{
			"https://www.postgresql.org/docs/13/runtime-config-logging.html#GUC-LOG-CONNECTIONS",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformPgLogConnectionsGoodExamples,
			BadExamples:         terraformPgLogConnectionsBadExamples,
			Links:               terraformPgLogConnectionsLinks,
			RemediationMarkdown: terraformPgLogConnectionsRemediationMarkdown,
		},
		Severity:   severity.Medium,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.Google.SQL.Instances {
			if instance.Metadata.IsUnmanaged() {
				continue
			}
			if instance.DatabaseFamily() != sql.DatabaseFamilyPostgres {
				continue
			}
			if instance.Settings.Flags.LogConnections.IsFalse() {
				results.Add(
					"Database instance is not configured to log connections.",
					instance.Settings.Flags.LogConnections,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)
