package database

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/database"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckSecureTlsPolicy(t *testing.T) {
	tests := []struct {
		name     string
		input    database.Database
		expected bool
	}{
		{
			name: "MS SQL server minimum TLS version 1.0",
			input: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:          trivyTypes.NewTestMetadata(),
							MinimumTLSVersion: trivyTypes.String("1.0", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "MySQL server minimum TLS version 1.0",
			input: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:          trivyTypes.NewTestMetadata(),
							MinimumTLSVersion: trivyTypes.String("TLS1_0", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "PostgreSQL server minimum TLS version 1.0",
			input: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:          trivyTypes.NewTestMetadata(),
							MinimumTLSVersion: trivyTypes.String("TLS1_0", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "MS SQL server minimum TLS version 1.2",
			input: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:          trivyTypes.NewTestMetadata(),
							MinimumTLSVersion: trivyTypes.String("1.2", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "MySQL server minimum TLS version 1.2",
			input: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:          trivyTypes.NewTestMetadata(),
							MinimumTLSVersion: trivyTypes.String("TLS1_2", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "PostgreSQL server minimum TLS version 1.2",
			input: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:          trivyTypes.NewTestMetadata(),
							MinimumTLSVersion: trivyTypes.String("TLS1_2", trivyTypes.NewTestMetadata()),
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
			results := CheckSecureTlsPolicy.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckSecureTlsPolicy.LongID() {
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
