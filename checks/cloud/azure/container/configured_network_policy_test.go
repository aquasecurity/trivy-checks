package container

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/container"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckConfiguredNetworkPolicy(t *testing.T) {
	tests := []struct {
		name     string
		input    container.Container
		expected bool
	}{
		{
			name: "Cluster missing network policy configuration",
			input: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NetworkProfile: container.NetworkProfile{
							Metadata:      trivyTypes.NewTestMetadata(),
							NetworkPolicy: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster with network policy configured",
			input: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NetworkProfile: container.NetworkProfile{
							Metadata:      trivyTypes.NewTestMetadata(),
							NetworkPolicy: trivyTypes.String("calico", trivyTypes.NewTestMetadata()),
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
			testState.Azure.Container = test.input
			results := CheckConfiguredNetworkPolicy.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckConfiguredNetworkPolicy.LongID() {
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
