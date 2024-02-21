package compute

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/compute"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckVmDiskEncryptionCustomerKey(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Instance disk missing encryption key link",
			input: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						BootDisks: []compute.Disk{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Encryption: compute.DiskEncryption{
									Metadata:   trivyTypes.NewTestMetadata(),
									KMSKeyLink: trivyTypes.String("", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Instance disk encryption key link provided",
			input: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						AttachedDisks: []compute.Disk{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Encryption: compute.DiskEncryption{
									Metadata:   trivyTypes.NewTestMetadata(),
									KMSKeyLink: trivyTypes.String("kms-key-link", trivyTypes.NewTestMetadata()),
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
			testState.Google.Compute = test.input
			results := CheckVmDiskEncryptionCustomerKey.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckVmDiskEncryptionCustomerKey.LongID() {
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
