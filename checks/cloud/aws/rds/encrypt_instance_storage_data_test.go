package rds

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/rds"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEncryptInstanceStorageData(t *testing.T) {
	tests := []struct {
		name     string
		input    rds.RDS
		expected bool
	}{
		{
			name: "RDS Instance with unencrypted storage",
			input: rds.RDS{
				Instances: []rds.Instance{
					{
						Metadata:             trivyTypes.NewTestMetadata(),
						ReplicationSourceARN: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						Encryption: rds.Encryption{
							Metadata:       trivyTypes.NewTestMetadata(),
							EncryptStorage: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "RDS Instance with encrypted storage",
			input: rds.RDS{
				Instances: []rds.Instance{
					{
						Metadata:             trivyTypes.NewTestMetadata(),
						ReplicationSourceARN: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						Encryption: rds.Encryption{
							Metadata:       trivyTypes.NewTestMetadata(),
							EncryptStorage: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
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
			results := CheckEncryptInstanceStorageData.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEncryptInstanceStorageData.LongID() {
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
