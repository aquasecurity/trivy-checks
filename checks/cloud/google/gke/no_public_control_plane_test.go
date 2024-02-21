package gke

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/gke"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicControlPlane(t *testing.T) {
	tests := []struct {
		name     string
		input    gke.GKE
		expected bool
	}{
		{
			name: "Master authorized network with public CIDR",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						MasterAuthorizedNetworks: gke.MasterAuthorizedNetworks{
							Metadata: trivyTypes.NewTestMetadata(),
							CIDRs: []trivyTypes.StringValue{
								trivyTypes.String("0.0.0.0/0", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Master authorized network with private CIDR",
			input: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						MasterAuthorizedNetworks: gke.MasterAuthorizedNetworks{
							Metadata: trivyTypes.NewTestMetadata(),
							CIDRs: []trivyTypes.StringValue{
								trivyTypes.String("10.10.128.0/24", trivyTypes.NewTestMetadata()),
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
			results := CheckNoPublicControlPlane.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicControlPlane.LongID() {
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
