package gke

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/gke"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNodeMetadataSecurity(t *testing.T) {
	tests := []struct {
		name     string
		input    gke.GKE
		expected bool
	}{
		{
			name: "Cluster node pools metadata exposed by default",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata: trivyTypes.NewTestMetadata(),
							WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
								Metadata:     trivyTypes.NewTestMetadata(),
								NodeMetadata: trivyTypes.String("UNSPECIFIED", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Node pool metadata exposed",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata: trivyTypes.NewTestMetadata(),
							WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
								Metadata:     trivyTypes.NewTestMetadata(),
								NodeMetadata: trivyTypes.String("SECURE", trivyTypes.NewTestMetadata()),
							},
						},
						NodePools: []gke.NodePool{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								NodeConfig: gke.NodeConfig{
									Metadata: trivyTypes.NewTestMetadata(),
									WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
										Metadata:     trivyTypes.NewTestMetadata(),
										NodeMetadata: trivyTypes.String("EXPOSE", trivyTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster node pools metadata secured",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata: trivyTypes.NewTestMetadata(),
							WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
								Metadata:     trivyTypes.NewTestMetadata(),
								NodeMetadata: trivyTypes.String("SECURE", trivyTypes.NewTestMetadata()),
							},
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
			results := CheckNodeMetadataSecurity.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNodeMetadataSecurity.LongID() {
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
