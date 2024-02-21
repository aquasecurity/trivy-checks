package elasticache

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

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
						Metadata:               trivyTypes.NewTestMetadata(),
						Engine:                 trivyTypes.String("redis", trivyTypes.NewTestMetadata()),
						NodeType:               trivyTypes.String("cache.m4.large", trivyTypes.NewTestMetadata()),
						SnapshotRetentionLimit: trivyTypes.Int(0, trivyTypes.NewTestMetadata()),
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
						Metadata:               trivyTypes.NewTestMetadata(),
						Engine:                 trivyTypes.String("redis", trivyTypes.NewTestMetadata()),
						NodeType:               trivyTypes.String("cache.m4.large", trivyTypes.NewTestMetadata()),
						SnapshotRetentionLimit: trivyTypes.Int(5, trivyTypes.NewTestMetadata()),
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
