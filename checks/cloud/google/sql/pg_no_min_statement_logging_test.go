package sql

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/sql"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckPgNoMinStatementLogging(t *testing.T) {
	tests := []struct {
		name     string
		input    sql.SQL
		expected bool
	}{
		{
			name: "Instance logging enabled for all statements",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						DatabaseVersion: trivyTypes.String("POSTGRES_12", trivyTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:                trivyTypes.NewTestMetadata(),
								LogMinDurationStatement: trivyTypes.Int(0, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Instance logging disabled for all statements",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						DatabaseVersion: trivyTypes.String("POSTGRES_12", trivyTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:                trivyTypes.NewTestMetadata(),
								LogMinDurationStatement: trivyTypes.Int(-1, trivyTypes.NewTestMetadata()),
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
			results := CheckPgNoMinStatementLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckPgNoMinStatementLogging.LongID() {
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
