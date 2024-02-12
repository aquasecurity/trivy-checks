package storage

import (
	"testing"

	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/storage"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckBucketEncryptionCustomerKey(t *testing.T) {
	tests := []struct {
		name     string
		input    storage.Storage
		expected bool
	}{
		{
			name: "Storage bucket missing default kms key name",
			input: storage.Storage{
				Buckets: []storage.Bucket{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Encryption: storage.BucketEncryption{
							Metadata:          defsecTypes.NewTestMetadata(),
							DefaultKMSKeyName: defsecTypes.String("", defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Storage bucket with default kms key name provided",
			input: storage.Storage{
				Buckets: []storage.Bucket{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Encryption: storage.BucketEncryption{
							Metadata:          defsecTypes.NewTestMetadata(),
							DefaultKMSKeyName: defsecTypes.String("default-kms-key-name", defsecTypes.NewTestMetadata()),
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
			testState.Google.Storage = test.input
			results := CheckBucketEncryptionCustomerKey.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckBucketEncryptionCustomerKey.LongID() {
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
