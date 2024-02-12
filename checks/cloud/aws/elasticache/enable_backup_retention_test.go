package elasticache

import (
	"testing"

	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/elasticache"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableBackupRetention(t *testing.T) {
	tests := []struct {
		name     string
		input    elasticache.ElastiCache
		expected bool
	}{
		{
			name: "Cluster snapshot retention days set to 0",
			input: elasticache.ElastiCache{
				Clusters: []elasticache.Cluster{
					{
						Metadata:               defsecTypes.NewTestMetadata(),
						Engine:                 defsecTypes.String("redis", defsecTypes.NewTestMetadata()),
						NodeType:               defsecTypes.String("cache.m4.large", defsecTypes.NewTestMetadata()),
						SnapshotRetentionLimit: defsecTypes.Int(0, defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster snapshot retention days set to 5",
			input: elasticache.ElastiCache{
				Clusters: []elasticache.Cluster{
					{
						Metadata:               defsecTypes.NewTestMetadata(),
						Engine:                 defsecTypes.String("redis", defsecTypes.NewTestMetadata()),
						NodeType:               defsecTypes.String("cache.m4.large", defsecTypes.NewTestMetadata()),
						SnapshotRetentionLimit: defsecTypes.Int(5, defsecTypes.NewTestMetadata()),
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
			results := CheckEnableBackupRetention.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableBackupRetention.LongID() {
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
