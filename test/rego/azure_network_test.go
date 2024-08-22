package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/network"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(azureNetworkTestCases)
}

var azureNetworkTestCases = testCases{
	"AVD-AZU-0048": {
		{
			name: "Security group inbound rule allowing RDP access from the Internet",
			input: state.State{Azure: azure.Azure{Network: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Outbound: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								Allow:    trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								SourceAddresses: []trivyTypes.StringValue{
									trivyTypes.String("*", trivyTypes.NewTestMetadata()),
								},
								SourcePorts:          nil,
								DestinationAddresses: nil,
								DestinationPorts: []network.PortRange{
									{
										Metadata: trivyTypes.NewTestMetadata(),
										Start:    trivyTypes.IntTest(3310),
										End:      trivyTypes.IntTest(3390),
									},
								},
								Protocol: trivyTypes.String("Tcp", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Security group inbound rule allowing RDP access from a specific address",
			input: state.State{Azure: azure.Azure{Network: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Allow:    trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								Outbound: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								DestinationPorts: []network.PortRange{
									{
										Metadata: trivyTypes.NewTestMetadata(),
										Start:    trivyTypes.IntTest(3310),
										End:      trivyTypes.IntTest(3390),
									},
								},
								SourceAddresses: []trivyTypes.StringValue{
									trivyTypes.String("4.53.160.75", trivyTypes.NewTestMetadata()),
								},
								Protocol: trivyTypes.String("Tcp", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Security group inbound rule allowing only ICMP",
			input: state.State{Azure: azure.Azure{Network: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Outbound: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								Allow:    trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								SourceAddresses: []trivyTypes.StringValue{
									trivyTypes.String("*", trivyTypes.NewTestMetadata()),
								},
								SourcePorts:          nil,
								DestinationAddresses: nil,
								DestinationPorts: []network.PortRange{
									{
										Metadata: trivyTypes.NewTestMetadata(),
										Start:    trivyTypes.IntTest(3310),
										End:      trivyTypes.IntTest(3390),
									},
								},
								Protocol: trivyTypes.String("Icmp", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0051": {
		{
			name: "Security group outbound rule with wildcard destination address",
			input: state.State{Azure: azure.Azure{Network: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Allow:    trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								Outbound: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								DestinationAddresses: []trivyTypes.StringValue{
									trivyTypes.String("*", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Security group outbound rule with private destination address",
			input: state.State{Azure: azure.Azure{Network: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Allow:    trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								Outbound: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								DestinationAddresses: []trivyTypes.StringValue{
									trivyTypes.String("10.0.0.0/16", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0047": {
		{
			name: "Security group inbound rule with wildcard source address",
			input: state.State{Azure: azure.Azure{Network: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Allow:    trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								Outbound: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								SourceAddresses: []trivyTypes.StringValue{
									trivyTypes.String("*", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Security group inbound rule with private source address",
			input: state.State{Azure: azure.Azure{Network: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Allow:    trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								Outbound: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								SourceAddresses: []trivyTypes.StringValue{
									trivyTypes.String("10.0.0.0/16", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0049": {
		{
			name: "Network watcher flow log retention policy disabled",
			input: state.State{Azure: azure.Azure{Network: network.Network{
				NetworkWatcherFlowLogs: []network.NetworkWatcherFlowLog{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						RetentionPolicy: network.RetentionPolicy{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							Days:     trivyTypes.Int(100, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Network watcher flow log retention policy enabled for 30 days",
			input: state.State{Azure: azure.Azure{Network: network.Network{
				NetworkWatcherFlowLogs: []network.NetworkWatcherFlowLog{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						RetentionPolicy: network.RetentionPolicy{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							Days:     trivyTypes.Int(30, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Network watcher flow log retention policy enabled for 100 days",
			input: state.State{Azure: azure.Azure{Network: network.Network{
				NetworkWatcherFlowLogs: []network.NetworkWatcherFlowLog{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						RetentionPolicy: network.RetentionPolicy{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							Days:     trivyTypes.Int(100, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0050": {
		{
			name: "Security group rule allowing SSH access from the public internet",
			input: state.State{Azure: azure.Azure{Network: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Allow:    trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								Outbound: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								DestinationPorts: []network.PortRange{
									{
										Metadata: trivyTypes.NewTestMetadata(),
										Start:    trivyTypes.IntTest(22),
										End:      trivyTypes.IntTest(22),
									},
								},
								SourceAddresses: []trivyTypes.StringValue{
									trivyTypes.String("*", trivyTypes.NewTestMetadata()),
								},
								Protocol: trivyTypes.String("Tcp", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Security group rule allowing SSH only ICMP",
			input: state.State{Azure: azure.Azure{Network: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Allow:    trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								Outbound: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								DestinationPorts: []network.PortRange{
									{
										Metadata: trivyTypes.NewTestMetadata(),
										Start:    trivyTypes.IntTest(22),
										End:      trivyTypes.IntTest(22),
									},
								},
								SourceAddresses: []trivyTypes.StringValue{
									trivyTypes.String("*", trivyTypes.NewTestMetadata()),
								},
								Protocol: trivyTypes.String("Icmp", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Security group rule allowing SSH access from a specific address",
			input: state.State{Azure: azure.Azure{Network: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Allow:    trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								Outbound: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								DestinationPorts: []network.PortRange{
									{
										Metadata: trivyTypes.NewTestMetadata(),
										Start:    trivyTypes.IntTest(22),
										End:      trivyTypes.IntTest(22),
									},
								},
								SourceAddresses: []trivyTypes.StringValue{
									trivyTypes.String("82.102.23.23", trivyTypes.NewTestMetadata()),
								},
								Protocol: trivyTypes.String("Tcp", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
