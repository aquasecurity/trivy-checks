package sql

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/sql"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnablePgTempFileLogging(t *testing.T) {
	tests := []struct {
		name     string
		input    sql.SQL
		expected bool
	}{
		{
			name: "Instance temp files logging disabled for all files",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						DatabaseVersion: trivyTypes.String("POSTGRES_12", trivyTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:        trivyTypes.NewTestMetadata(),
								LogTempFileSize: trivyTypes.Int(-1, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Instance temp files logging disabled for files smaller than 100KB",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						DatabaseVersion: trivyTypes.String("POSTGRES_12", trivyTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:        trivyTypes.NewTestMetadata(),
								LogTempFileSize: trivyTypes.Int(100, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Instance temp files logging enabled for all files",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						DatabaseVersion: trivyTypes.String("POSTGRES_12", trivyTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:        trivyTypes.NewTestMetadata(),
								LogTempFileSize: trivyTypes.Int(0, trivyTypes.NewTestMetadata()),
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
			results := CheckEnablePgTempFileLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnablePgTempFileLogging.LongID() {
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
