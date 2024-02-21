package container

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/container"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckLimitAuthorizedIps(t *testing.T) {
	tests := []struct {
		name     string
		input    container.Container
		expected bool
	}{
		{
			name: "API server authorized IP ranges undefined",
			input: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata:                    trivyTypes.NewTestMetadata(),
						EnablePrivateCluster:        trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						APIServerAuthorizedIPRanges: []trivyTypes.StringValue{},
					},
				},
			},
			expected: true,
		},
		{
			name: "API server authorized IP ranges defined",
			input: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata:             trivyTypes.NewTestMetadata(),
						EnablePrivateCluster: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						APIServerAuthorizedIPRanges: []trivyTypes.StringValue{
							trivyTypes.String("1.2.3.4/32", trivyTypes.NewTestMetadata()),
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
			results := CheckLimitAuthorizedIps.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckLimitAuthorizedIps.LongID() {
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
