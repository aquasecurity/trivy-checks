package kms

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/kms"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckRotateKmsKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    kms.KMS
		expected bool
	}{
		{
			name: "KMS key rotation period of 91 days",
			input: kms.KMS{
				KeyRings: []kms.KeyRing{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Keys: []kms.Key{
							{
								Metadata:              trivyTypes.NewTestMetadata(),
								RotationPeriodSeconds: trivyTypes.Int(7862400, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "KMS key rotation period of 30 days",
			input: kms.KMS{
				KeyRings: []kms.KeyRing{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Keys: []kms.Key{
							{
								Metadata:              trivyTypes.NewTestMetadata(),
								RotationPeriodSeconds: trivyTypes.Int(2592000, trivyTypes.NewTestMetadata()),
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
			testState.Google.KMS = test.input
			results := CheckRotateKmsKeys.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckRotateKmsKeys.LongID() {
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
