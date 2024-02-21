package dynamodb

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/dynamodb"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckTableCustomerKey(t *testing.T) {
	tests := []struct {
		name     string
		input    dynamodb.DynamoDB
		expected bool
	}{
		{
			name: "Cluster encryption missing KMS key",
			input: dynamodb.DynamoDB{
				Tables: []dynamodb.Table{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ServerSideEncryption: dynamodb.ServerSideEncryption{
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							Metadata: trivyTypes.NewTestMetadata(),
							KMSKeyID: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster encryption using default KMS key",
			input: dynamodb.DynamoDB{
				Tables: []dynamodb.Table{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ServerSideEncryption: dynamodb.ServerSideEncryption{
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							Metadata: trivyTypes.NewTestMetadata(),
							KMSKeyID: trivyTypes.String(dynamodb.DefaultKMSKeyID, trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster encryption using proper KMS key",
			input: dynamodb.DynamoDB{
				Tables: []dynamodb.Table{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ServerSideEncryption: dynamodb.ServerSideEncryption{
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							Metadata: trivyTypes.NewTestMetadata(),
							KMSKeyID: trivyTypes.String("some-ok-key", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "KMS key exist, but SSE is not enabled",
			input: dynamodb.DynamoDB{
				Tables: []dynamodb.Table{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ServerSideEncryption: dynamodb.ServerSideEncryption{
							Enabled:  trivyTypes.BoolDefault(false, trivyTypes.NewTestMetadata()),
							Metadata: trivyTypes.NewTestMetadata(),
							KMSKeyID: trivyTypes.String("some-ok-key", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.DynamoDB = test.input
			results := CheckTableCustomerKey.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckTableCustomerKey.LongID() {
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
