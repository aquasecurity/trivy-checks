package eks

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/eks"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEncryptSecrets(t *testing.T) {
	tests := []struct {
		name     string
		input    eks.EKS
		expected bool
	}{
		{
			name: "EKS Cluster with no secrets in the resources attribute",
			input: eks.EKS{
				Clusters: []eks.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: eks.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							Secrets:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							KMSKeyID: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "EKS Cluster with secrets in the resources attribute but no KMS key",
			input: eks.EKS{
				Clusters: []eks.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: eks.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							Secrets:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							KMSKeyID: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "EKS Cluster with secrets in the resources attribute and a KMS key",
			input: eks.EKS{
				Clusters: []eks.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: eks.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							Secrets:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							KMSKeyID: trivyTypes.String("some-arn", trivyTypes.NewTestMetadata()),
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
			testState.AWS.EKS = test.input
			results := CheckEncryptSecrets.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEncryptSecrets.LongID() {
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
