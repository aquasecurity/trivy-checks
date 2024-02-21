package database

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/database"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckRetentionPeriodSet(t *testing.T) {
	tests := []struct {
		name     string
		input    database.Database
		expected bool
	}{
		{
			name: "MS SQL server auditing policy with retention period of 30 days",
			input: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ExtendedAuditingPolicies: []database.ExtendedAuditingPolicy{
							{
								Metadata:        trivyTypes.NewTestMetadata(),
								RetentionInDays: trivyTypes.Int(30, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "MS SQL server auditing policy with retention period of 90 days",
			input: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ExtendedAuditingPolicies: []database.ExtendedAuditingPolicy{
							{
								Metadata:        trivyTypes.NewTestMetadata(),
								RetentionInDays: trivyTypes.Int(90, trivyTypes.NewTestMetadata()),
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
			testState.Azure.Database = test.input
			results := CheckRetentionPeriodSet.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckRetentionPeriodSet.LongID() {
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
