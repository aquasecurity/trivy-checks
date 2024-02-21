package elb

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/elb"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckDropInvalidHeaders(t *testing.T) {
	tests := []struct {
		name     string
		input    elb.ELB
		expected bool
	}{
		{
			name: "Load balancer drop invalid headers disabled",
			input: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata:                trivyTypes.NewTestMetadata(),
						Type:                    trivyTypes.String(elb.TypeApplication, trivyTypes.NewTestMetadata()),
						DropInvalidHeaderFields: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Load balancer drop invalid headers enabled",
			input: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata:                trivyTypes.NewTestMetadata(),
						Type:                    trivyTypes.String(elb.TypeApplication, trivyTypes.NewTestMetadata()),
						DropInvalidHeaderFields: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		}, {
			name: "Classic load balanace doesn't fail when no drop headers",
			input: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Type:     trivyTypes.String(elb.TypeClassic, trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.ELB = test.input
			results := CheckDropInvalidHeaders.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckDropInvalidHeaders.LongID() {
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
