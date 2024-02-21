package dynamodb

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/dynamodb"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableRecovery(t *testing.T) {
	tests := []struct {
		name     string
		input    dynamodb.DynamoDB
		expected bool
	}{
		{
			name: "Cluster with point in time recovery disabled",
			input: dynamodb.DynamoDB{
				DAXClusters: []dynamodb.DAXCluster{
					{
						Metadata:            trivyTypes.NewTestMetadata(),
						PointInTimeRecovery: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster with point in time recovery enabled",
			input: dynamodb.DynamoDB{
				DAXClusters: []dynamodb.DAXCluster{
					{
						Metadata:            trivyTypes.NewTestMetadata(),
						PointInTimeRecovery: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.DynamoDB = test.input
			results := CheckEnableRecovery.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableRecovery.LongID() {
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
