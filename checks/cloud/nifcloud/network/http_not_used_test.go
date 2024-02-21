package network

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/network"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckHttpNotUsed(t *testing.T) {
	tests := []struct {
		name     string
		input    network.Network
		expected bool
	}{
		{
			name: "Elastic Load balancer listener with HTTP protocol on global",
			input: network.Network{
				ElasticLoadBalancers: []network.ElasticLoadBalancer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NetworkInterfaces: []network.NetworkInterface{{
							Metadata:     trivyTypes.NewTestMetadata(),
							NetworkID:    trivyTypes.String("net-COMMON_GLOBAL", trivyTypes.NewTestMetadata()),
							IsVipNetwork: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						}},
						Listeners: []network.ElasticLoadBalancerListener{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Protocol: trivyTypes.String("HTTP", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Elastic Load balancer listener with HTTP protocol on internal",
			input: network.Network{
				ElasticLoadBalancers: []network.ElasticLoadBalancer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NetworkInterfaces: []network.NetworkInterface{{
							Metadata:     trivyTypes.NewTestMetadata(),
							NetworkID:    trivyTypes.String("some-network", trivyTypes.NewTestMetadata()),
							IsVipNetwork: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						}},
						Listeners: []network.ElasticLoadBalancerListener{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Protocol: trivyTypes.String("HTTP", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Elastic Load balancer listener with HTTPS protocol on global",
			input: network.Network{
				ElasticLoadBalancers: []network.ElasticLoadBalancer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NetworkInterfaces: []network.NetworkInterface{{
							Metadata:     trivyTypes.NewTestMetadata(),
							NetworkID:    trivyTypes.String("net-COMMON_GLOBAL", trivyTypes.NewTestMetadata()),
							IsVipNetwork: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						}},
						Listeners: []network.ElasticLoadBalancerListener{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Protocol: trivyTypes.String("HTTPS", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Load balancer listener with HTTP protocol",
			input: network.Network{
				LoadBalancers: []network.LoadBalancer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Listeners: []network.LoadBalancerListener{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Protocol: trivyTypes.String("HTTP", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Load balancer listener with HTTPS protocol",
			input: network.Network{
				LoadBalancers: []network.LoadBalancer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Listeners: []network.LoadBalancerListener{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Protocol: trivyTypes.String("HTTPS", trivyTypes.NewTestMetadata()),
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
			results := CheckHttpNotUsed.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckHttpNotUsed.LongID() {
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
