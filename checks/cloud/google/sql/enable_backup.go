package sql

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckEnableBackup = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0024",
		Provider:    providers.GoogleProvider,
		Service:     "sql",
		ShortCode:   "enable-backup",
		Summary:     "Enable automated backups to recover from data-loss",
		Impact:      "No recovery of lost or corrupted data",
		Resolution:  "Enable automated backups",
		Explanation: `Automated backups are not enabled by default. Backups are an easy way to restore data in a corruption or data-loss scenario.`,
		Links: []string{
			"https://cloud.google.com/sql/docs/mysql/backup-recovery/backups",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableBackupGoodExamples,
			BadExamples:         terraformEnableBackupBadExamples,
			Links:               terraformEnableBackupLinks,
			RemediationMarkdown: terraformEnableBackupRemediationMarkdown,
		},
		Severity:   severity.Medium,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.Google.SQL.Instances {
			if instance.Metadata.IsUnmanaged() || instance.IsReplica.IsTrue() {
				continue
			}
			if instance.Settings.Backups.Enabled.IsFalse() {
				results.Add(
					"Database instance does not have backups enabled.",
					instance.Settings.Backups.Enabled,
				)
			} else {
				results.AddPassed(&instance)
			}

		}
		return
	},
)
