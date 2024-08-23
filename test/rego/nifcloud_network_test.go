package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud"
	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/network"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

var nifcloudNetworkTestCases = testCases{
	"AVD-NIF-0016": {
		{
			name: "NIFCLOUD router with no security group provided",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
				Routers: []network.Router{
					{
						Metadata:      trivyTypes.NewTestMetadata(),
						SecurityGroup: trivyTypes.String("", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD router with security group",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
				Routers: []network.Router{
					{
						Metadata:      trivyTypes.NewTestMetadata(),
						SecurityGroup: trivyTypes.String("some security group", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-NIF-0018": {
		{
			name: "NIFCLOUD vpnGateway with no security group provided",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
				VpnGateways: []network.VpnGateway{
					{
						Metadata:      trivyTypes.NewTestMetadata(),
						SecurityGroup: trivyTypes.String("", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD vpnGateway with security group",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
				VpnGateways: []network.VpnGateway{
					{
						Metadata:      trivyTypes.NewTestMetadata(),
						SecurityGroup: trivyTypes.String("some security group", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-NIF-0021": {
		{
			name: "Elastic Load balancer listener with HTTP protocol on global",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
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
			}}},
			expected: true,
		},
		{
			name: "Elastic Load balancer listener with HTTP protocol on internal",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
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
			}}},
			expected: false,
		},
		{
			name: "Elastic Load balancer listener with HTTPS protocol on global",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
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
			}}},
			expected: false,
		},
		{
			name: "Load balancer listener with HTTP protocol",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
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
			}}},
			expected: true,
		},
		{
			name: "Load balancer listener with HTTPS protocol",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
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
			}}},
			expected: false,
		},
	},
	"AVD-NIF-0019": {
		{
			name: "NIFCLOUD elb with common private",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
				ElasticLoadBalancers: []network.ElasticLoadBalancer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NetworkInterfaces: []network.NetworkInterface{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								NetworkID: trivyTypes.String("net-COMMON_PRIVATE", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD elb with private LAN",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
				ElasticLoadBalancers: []network.ElasticLoadBalancer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NetworkInterfaces: []network.NetworkInterface{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								NetworkID: trivyTypes.String("net-some-private-lan", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-NIF-0017": {
		{
			name: "NIFCLOUD router with common private",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
				Routers: []network.Router{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NetworkInterfaces: []network.NetworkInterface{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								NetworkID: trivyTypes.String("net-COMMON_PRIVATE", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD router with private LAN",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
				Routers: []network.Router{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NetworkInterfaces: []network.NetworkInterface{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								NetworkID: trivyTypes.String("net-some-private-lan", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-NIF-0020": {
		{
			name: "Load balancer listener using TLS v1.0",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
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
			}}},
			expected: true,
		},
		{
			name: "Load balancer listener using TLS v1.2",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
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
			}}},
			expected: false,
		},
		{
			name: "Load balancer listener using ICMP",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
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
			}}},
			expected: false,
		},
	},
}
