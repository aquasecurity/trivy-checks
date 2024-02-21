package eks

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/eks"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableControlPlaneLogging(t *testing.T) {
	tests := []struct {
		name     string
		input    eks.EKS
		expected bool
	}{
		{
			name: "EKS cluster with all cluster logging disabled",
			input: eks.EKS{
				Clusters: []eks.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Logging: eks.Logging{
							API:               trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							Audit:             trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							Authenticator:     trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							ControllerManager: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							Scheduler:         trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "EKS cluster with only some cluster logging enabled",
			input: eks.EKS{
				Clusters: []eks.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Logging: eks.Logging{
							API:               trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							Audit:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							Authenticator:     trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							ControllerManager: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							Scheduler:         trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "EKS cluster with all cluster logging enabled",
			input: eks.EKS{
				Clusters: []eks.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Logging: eks.Logging{
							API:               trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							Audit:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							Authenticator:     trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							ControllerManager: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							Scheduler:         trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
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
			testState.AWS.EKS = test.input
			results := CheckEnableControlPlaneLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableControlPlaneLogging.LongID() {
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
