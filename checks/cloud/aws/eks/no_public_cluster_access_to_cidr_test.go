package eks

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/eks"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicClusterAccessToCidr(t *testing.T) {
	tests := []struct {
		name     string
		input    eks.EKS
		expected bool
	}{
		{
			name: "EKS Cluster with public access CIDRs actively set to open",
			input: eks.EKS{
				Clusters: []eks.Cluster{
					{
						PublicAccessEnabled: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						PublicAccessCIDRs: []trivyTypes.StringValue{
							trivyTypes.String("0.0.0.0/0", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "EKS Cluster with public access enabled but private CIDRs",
			input: eks.EKS{
				Clusters: []eks.Cluster{
					{
						PublicAccessEnabled: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						PublicAccessCIDRs: []trivyTypes.StringValue{
							trivyTypes.String("10.2.0.0/8", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "EKS Cluster with public access disabled and private CIDRs",
			input: eks.EKS{
				Clusters: []eks.Cluster{
					{
						PublicAccessEnabled: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						PublicAccessCIDRs: []trivyTypes.StringValue{
							trivyTypes.String("10.2.0.0/8", trivyTypes.NewTestMetadata()),
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
			results := CheckNoPublicClusterAccessToCidr.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicClusterAccessToCidr.LongID() {
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
