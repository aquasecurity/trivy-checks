package gke

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/gke"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckMetadataEndpointsDisabled(t *testing.T) {
	tests := []struct {
		name     string
		input    gke.GKE
		expected bool
	}{
		{
			name: "Cluster legacy metadata endpoints enabled",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:              trivyTypes.NewTestMetadata(),
							EnableLegacyEndpoints: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
						RemoveDefaultNodePool: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster legacy metadata endpoints disabled",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:              trivyTypes.NewTestMetadata(),
							EnableLegacyEndpoints: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
						RemoveDefaultNodePool: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "Cluster legacy metadata endpoints disabled on non-default node pool",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:              trivyTypes.NewTestMetadata(),
							EnableLegacyEndpoints: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
						RemoveDefaultNodePool: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						NodePools: []gke.NodePool{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								NodeConfig: gke.NodeConfig{
									EnableLegacyEndpoints: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Cluster legacy metadata endpoints enabled on non-default node pool",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:              trivyTypes.NewTestMetadata(),
							EnableLegacyEndpoints: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
						RemoveDefaultNodePool: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						NodePools: []gke.NodePool{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								NodeConfig: gke.NodeConfig{
									EnableLegacyEndpoints: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								},
							},
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
			testState.Google.GKE = test.input
			results := CheckMetadataEndpointsDisabled.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckMetadataEndpointsDisabled.LongID() {
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
