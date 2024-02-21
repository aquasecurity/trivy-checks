package database

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/database"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckThreatAlertEmailSet(t *testing.T) {
	tests := []struct {
		name     string
		input    database.Database
		expected bool
	}{
		{
			name: "No email address provided for threat alerts",
			input: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						SecurityAlertPolicies: []database.SecurityAlertPolicy{
							{
								Metadata:       trivyTypes.NewTestMetadata(),
								EmailAddresses: []trivyTypes.StringValue{},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Email address provided for threat alerts",
			input: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						SecurityAlertPolicies: []database.SecurityAlertPolicy{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								EmailAddresses: []trivyTypes.StringValue{
									trivyTypes.String("sample@email.com", trivyTypes.NewTestMetadata()),
								},
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
			results := CheckThreatAlertEmailSet.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckThreatAlertEmailSet.LongID() {
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
