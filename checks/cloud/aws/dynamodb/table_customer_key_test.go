package dynamodb

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/aws/dynamodb"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/state"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
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
						Metadata: defsecTypes.NewTestMetadata(),
						ServerSideEncryption: dynamodb.ServerSideEncryption{
							Enabled:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							Metadata: defsecTypes.NewTestMetadata(),
							KMSKeyID: defsecTypes.String("", defsecTypes.NewTestMetadata()),
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
						Metadata: defsecTypes.NewTestMetadata(),
						ServerSideEncryption: dynamodb.ServerSideEncryption{
							Enabled:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							Metadata: defsecTypes.NewTestMetadata(),
							KMSKeyID: defsecTypes.String(dynamodb.DefaultKMSKeyID, defsecTypes.NewTestMetadata()),
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
						Metadata: defsecTypes.NewTestMetadata(),
						ServerSideEncryption: dynamodb.ServerSideEncryption{
							Enabled:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							Metadata: defsecTypes.NewTestMetadata(),
							KMSKeyID: defsecTypes.String("some-ok-key", defsecTypes.NewTestMetadata()),
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
						Metadata: defsecTypes.NewTestMetadata(),
						ServerSideEncryption: dynamodb.ServerSideEncryption{
							Enabled:  defsecTypes.BoolDefault(false, defsecTypes.NewTestMetadata()),
							Metadata: defsecTypes.NewTestMetadata(),
							KMSKeyID: defsecTypes.String("some-ok-key", defsecTypes.NewTestMetadata()),
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
