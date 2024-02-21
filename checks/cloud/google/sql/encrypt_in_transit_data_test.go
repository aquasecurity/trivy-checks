package sql

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/sql"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEncryptInTransitData(t *testing.T) {
	tests := []struct {
		name     string
		input    sql.SQL
		expected bool
	}{
		{
			name: "DB instance TLS not required",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							IPConfiguration: sql.IPConfiguration{
								Metadata:   trivyTypes.NewTestMetadata(),
								RequireTLS: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "DB instance TLS required",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							IPConfiguration: sql.IPConfiguration{
								Metadata:   trivyTypes.NewTestMetadata(),
								RequireTLS: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
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
			results := CheckEncryptInTransitData.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEncryptInTransitData.LongID() {
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
