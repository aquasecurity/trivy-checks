package rds

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/rds"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEncryptClusterStorageData(t *testing.T) {
	tests := []struct {
		name     string
		input    rds.RDS
		expected bool
	}{
		{
			name: "RDS Cluster with storage encryption disabled",
			input: rds.RDS{
				Clusters: []rds.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: rds.Encryption{
							Metadata:       trivyTypes.NewTestMetadata(),
							EncryptStorage: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							KMSKeyID:       trivyTypes.String("kms-key", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "RDS Cluster with storage encryption enabled but missing KMS key",
			input: rds.RDS{
				Clusters: []rds.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: rds.Encryption{
							Metadata:       trivyTypes.NewTestMetadata(),
							EncryptStorage: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							KMSKeyID:       trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "RDS Cluster with storage encryption enabled and KMS key provided",
			input: rds.RDS{
				Clusters: []rds.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: rds.Encryption{
							Metadata:       trivyTypes.NewTestMetadata(),
							EncryptStorage: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							KMSKeyID:       trivyTypes.String("kms-key", trivyTypes.NewTestMetadata()),
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
			testState.AWS.RDS = test.input
			results := CheckEncryptClusterStorageData.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEncryptClusterStorageData.LongID() {
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
