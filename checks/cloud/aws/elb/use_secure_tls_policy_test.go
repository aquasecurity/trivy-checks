package elb

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/elb"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckUseSecureTlsPolicy(t *testing.T) {
	tests := []struct {
		name     string
		input    elb.ELB
		expected bool
	}{
		{
			name: "Load balancer listener using TLS v1.0",
			input: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Listeners: []elb.Listener{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								TLSPolicy: trivyTypes.String("ELBSecurityPolicy-TLS-1-0-2015-04", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Load balancer listener using TLS v1.2",
			input: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Listeners: []elb.Listener{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								TLSPolicy: trivyTypes.String("ELBSecurityPolicy-TLS-1-2-2017-01", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Load balancer listener using TLS v1.3",
			input: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Listeners: []elb.Listener{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								TLSPolicy: trivyTypes.String("ELBSecurityPolicy-TLS13-1-2-2021-06", trivyTypes.NewTestMetadata()),
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
			testState.AWS.ELB = test.input
			results := CheckUseSecureTlsPolicy.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckUseSecureTlsPolicy.LongID() {
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
