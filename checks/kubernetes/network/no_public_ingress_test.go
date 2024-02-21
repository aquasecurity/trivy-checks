package network

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/kubernetes"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicIngress(t *testing.T) {
	tests := []struct {
		name     string
		input    []kubernetes.NetworkPolicy
		expected bool
	}{
		{
			name: "Public source CIDR",
			input: []kubernetes.NetworkPolicy{
				{
					Metadata: trivyTypes.NewTestMetadata(),
					Spec: kubernetes.NetworkPolicySpec{
						Metadata: trivyTypes.NewTestMetadata(),
						Ingress: kubernetes.Ingress{
							Metadata: trivyTypes.NewTestMetadata(),
							SourceCIDRs: []trivyTypes.StringValue{
								trivyTypes.String("0.0.0.0/0", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Private source CIDR",
			input: []kubernetes.NetworkPolicy{
				{
					Metadata: trivyTypes.NewTestMetadata(),
					Spec: kubernetes.NetworkPolicySpec{
						Metadata: trivyTypes.NewTestMetadata(),
						Ingress: kubernetes.Ingress{
							Metadata: trivyTypes.NewTestMetadata(),
							SourceCIDRs: []trivyTypes.StringValue{
								trivyTypes.String("10.0.0.0/16", trivyTypes.NewTestMetadata()),
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
			testState.Kubernetes.NetworkPolicies = test.input
			results := CheckNoPublicIngress.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicIngress.LongID() {
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
