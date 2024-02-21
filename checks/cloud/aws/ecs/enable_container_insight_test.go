package ecs

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ecs"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableContainerInsight(t *testing.T) {
	tests := []struct {
		name     string
		input    ecs.ECS
		expected bool
	}{
		{
			name: "Cluster with disabled container insights",
			input: ecs.ECS{
				Clusters: []ecs.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Settings: ecs.ClusterSettings{
							Metadata:                 trivyTypes.NewTestMetadata(),
							ContainerInsightsEnabled: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster with enabled container insights",
			input: ecs.ECS{
				Clusters: []ecs.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Settings: ecs.ClusterSettings{
							Metadata:                 trivyTypes.NewTestMetadata(),
							ContainerInsightsEnabled: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
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
			testState.AWS.ECS = test.input
			results := CheckEnableContainerInsight.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableContainerInsight.LongID() {
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
