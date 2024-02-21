package elasticache

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/elasticache"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableAtRestEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    elasticache.ElastiCache
		expected bool
	}{
		{
			name: "ElastiCache replication group with at-rest encryption disabled",
			input: elasticache.ElastiCache{
				ReplicationGroups: []elasticache.ReplicationGroup{
					{
						Metadata:                trivyTypes.NewTestMetadata(),
						AtRestEncryptionEnabled: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "ElastiCache replication group with at-rest encryption enabled",
			input: elasticache.ElastiCache{
				ReplicationGroups: []elasticache.ReplicationGroup{
					{
						Metadata:                trivyTypes.NewTestMetadata(),
						AtRestEncryptionEnabled: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.ElastiCache = test.input
			results := CheckEnableAtRestEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableAtRestEncryption.LongID() {
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
