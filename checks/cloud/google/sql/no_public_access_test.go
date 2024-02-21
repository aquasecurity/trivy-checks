package sql

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/sql"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicAccess(t *testing.T) {
	tests := []struct {
		name     string
		input    sql.SQL
		expected bool
	}{
		{
			name: "Instance settings set with IPv4 enabled",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							IPConfiguration: sql.IPConfiguration{
								Metadata:   trivyTypes.NewTestMetadata(),
								EnableIPv4: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Instance settings set with IPv4 disabled but public CIDR in authorized networks",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							IPConfiguration: sql.IPConfiguration{
								Metadata:   trivyTypes.NewTestMetadata(),
								EnableIPv4: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								AuthorizedNetworks: []struct {
									Name trivyTypes.StringValue
									CIDR trivyTypes.StringValue
								}{
									{
										CIDR: trivyTypes.String("0.0.0.0/0", trivyTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Instance settings set with IPv4 disabled and private CIDR",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Settings: sql.Settings{
							Metadata: trivyTypes.NewTestMetadata(),
							IPConfiguration: sql.IPConfiguration{
								Metadata:   trivyTypes.NewTestMetadata(),
								EnableIPv4: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								AuthorizedNetworks: []struct {
									Name trivyTypes.StringValue
									CIDR trivyTypes.StringValue
								}{
									{
										CIDR: trivyTypes.String("10.0.0.1/24", trivyTypes.NewTestMetadata()),
									},
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
			testState.Google.SQL = test.input
			results := CheckNoPublicAccess.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicAccess.LongID() {
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
