package kms

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/kms"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckAutoRotateKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    kms.KMS
		expected bool
	}{
		{
			name: "ENCRYPT_DECRYPT KMS Key with auto-rotation disabled",
			input: kms.KMS{
				Keys: []kms.Key{
					{
						Usage:           trivyTypes.String("ENCRYPT_DECRYPT", trivyTypes.NewTestMetadata()),
						RotationEnabled: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "ENCRYPT_DECRYPT KMS Key with auto-rotation enabled",
			input: kms.KMS{
				Keys: []kms.Key{
					{
						Usage:           trivyTypes.String("ENCRYPT_DECRYPT", trivyTypes.NewTestMetadata()),
						RotationEnabled: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "SIGN_VERIFY KMS Key with auto-rotation disabled",
			input: kms.KMS{
				Keys: []kms.Key{
					{
						Usage:           trivyTypes.String(kms.KeyUsageSignAndVerify, trivyTypes.NewTestMetadata()),
						RotationEnabled: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.KMS = test.input
			results := CheckAutoRotateKeys.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckAutoRotateKeys.LongID() {
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
