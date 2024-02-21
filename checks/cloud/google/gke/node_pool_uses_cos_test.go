package gke

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/gke"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNodePoolUsesCos(t *testing.T) {
	tests := []struct {
		name     string
		input    gke.GKE
		expected bool
	}{
		{
			name: "Cluster node config image type set to Ubuntu",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:  trivyTypes.NewTestMetadata(),
							ImageType: trivyTypes.String("UBUNTU", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster node pool image type set to Ubuntu",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:  trivyTypes.NewTestMetadata(),
							ImageType: trivyTypes.String("COS", trivyTypes.NewTestMetadata()),
						},
						NodePools: []gke.NodePool{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								NodeConfig: gke.NodeConfig{
									Metadata:  trivyTypes.NewTestMetadata(),
									ImageType: trivyTypes.String("UBUNTU", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster node config image type set to Container-Optimized OS",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:  trivyTypes.NewTestMetadata(),
							ImageType: trivyTypes.String("COS_CONTAINERD", trivyTypes.NewTestMetadata()),
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
			testState.Google.GKE = test.input
			results := CheckNodePoolUsesCos.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNodePoolUsesCos.LongID() {
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
