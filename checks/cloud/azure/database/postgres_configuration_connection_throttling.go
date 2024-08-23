package database

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckPostgresConfigurationLogConnectionThrottling = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AZU-0021",
		Provider:    providers.AzureProvider,
		Service:     "database",
		ShortCode:   "postgres-configuration-connection-throttling",
		Summary:     "Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database Server",
		Impact:      "No log information to help diagnosing connection contention issues",
		Resolution:  "Enable connection throttling logging",
		Explanation: `Postgresql can generate logs for connection throttling to improve visibility for audit and configuration issue resolution.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/postgresql/concepts-server-logs#configure-logging",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformPostgresConfigurationConnectionThrottlingGoodExamples,
			BadExamples:         terraformPostgresConfigurationConnectionThrottlingBadExamples,
			Links:               terraformPostgresConfigurationConnectionThrottlingLinks,
			RemediationMarkdown: terraformPostgresConfigurationConnectionThrottlingRemediationMarkdown,
		},
		Severity:   severity.Medium,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, server := range s.Azure.Database.PostgreSQLServers {
			if server.Metadata.IsUnmanaged() {
				continue
			}
			if server.Config.ConnectionThrottling.IsFalse() {
				results.Add(
					"Database server is not configured to throttle connections.",
					server.Config.ConnectionThrottling,
				)
			} else {
				results.AddPassed(&server.Config)
			}
		}
		return
	},
)
