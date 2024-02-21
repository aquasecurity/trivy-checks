package ecr

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ecr"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckRepositoryCustomerKey(t *testing.T) {
	tests := []struct {
		name     string
		input    ecr.ECR
		expected bool
	}{
		{
			name: "ECR repository not using KMS encryption",
			input: ecr.ECR{
				Repositories: []ecr.Repository{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: ecr.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							Type:     trivyTypes.String(ecr.EncryptionTypeAES256, trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "ECR repository using KMS encryption but missing key",
			input: ecr.ECR{
				Repositories: []ecr.Repository{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: ecr.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							Type:     trivyTypes.String(ecr.EncryptionTypeKMS, trivyTypes.NewTestMetadata()),
							KMSKeyID: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "ECR repository encrypted with KMS key",
			input: ecr.ECR{
				Repositories: []ecr.Repository{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: ecr.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							Type:     trivyTypes.String(ecr.EncryptionTypeKMS, trivyTypes.NewTestMetadata()),
							KMSKeyID: trivyTypes.String("some-kms-key", trivyTypes.NewTestMetadata()),
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
			testState.AWS.ECR = test.input
			results := CheckRepositoryCustomerKey.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckRepositoryCustomerKey.LongID() {
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
