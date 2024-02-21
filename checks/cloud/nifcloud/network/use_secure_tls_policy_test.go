package network

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/network"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckUseSecureTlsPolicy(t *testing.T) {
	tests := []struct {
		name     string
		input    network.Network
		expected bool
	}{
		{
			name: "Load balancer listener using TLS v1.0",
			input: network.Network{
				LoadBalancers: []network.LoadBalancer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Listeners: []network.LoadBalancerListener{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								TLSPolicy: trivyTypes.String("Standard Ciphers A ver1", trivyTypes.NewTestMetadata()),
								Protocol:  trivyTypes.String("HTTPS", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Load balancer listener using TLS v1.2",
			input: network.Network{
				LoadBalancers: []network.LoadBalancer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Listeners: []network.LoadBalancerListener{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								TLSPolicy: trivyTypes.String("Standard Ciphers D ver1", trivyTypes.NewTestMetadata()),
								Protocol:  trivyTypes.String("HTTPS", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Load balancer listener using ICMP",
			input: network.Network{
				LoadBalancers: []network.LoadBalancer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Listeners: []network.LoadBalancerListener{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								TLSPolicy: trivyTypes.String("", trivyTypes.NewTestMetadata()),
								Protocol:  trivyTypes.String("ICMP", trivyTypes.NewTestMetadata()),
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
			testState.Nifcloud.Network = test.input
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
