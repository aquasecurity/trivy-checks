package sql

import (
	"testing"

	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/sql"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableBackup(t *testing.T) {
	tests := []struct {
		name     string
		input    sql.SQL
		expected bool
	}{
		{
			name: "Database instance backups disabled",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:  defsecTypes.NewTestMetadata(),
						IsReplica: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: defsecTypes.NewTestMetadata(),
							Backups: sql.Backups{
								Metadata: defsecTypes.NewTestMetadata(),
								Enabled:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Database instance backups enabled",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:  defsecTypes.NewTestMetadata(),
						IsReplica: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: defsecTypes.NewTestMetadata(),
							Backups: sql.Backups{
								Metadata: defsecTypes.NewTestMetadata(),
								Enabled:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Read replica does not require backups",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:  defsecTypes.NewTestMetadata(),
						IsReplica: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: defsecTypes.NewTestMetadata(),
							Backups: sql.Backups{
								Metadata: defsecTypes.NewTestMetadata(),
								Enabled:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Google.SQL = test.input
			results := CheckEnableBackup.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableBackup.LongID() {
					found = true
				}
			}
			if test.expected {
				assert.True(t, found, "Rule should have been found")
			} else {
				assert.False(t, found, "Rule should not have been found")
			}
		})
	}
}
