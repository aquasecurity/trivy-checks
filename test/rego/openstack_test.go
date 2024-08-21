package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/openstack"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

var openStackTestCases = testCases{
	"AVD-OPNSTK-0001": {
		{
			name: "Instance admin with plaintext password set",
			input: state.State{OpenStack: openstack.OpenStack{Compute: openstack.Compute{
				Instances: []openstack.Instance{
					{
						Metadata:      trivyTypes.NewTestMetadata(),
						AdminPassword: trivyTypes.String("very-secret", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance admin with no plaintext password",
			input: state.State{OpenStack: openstack.OpenStack{Compute: openstack.Compute{
				Instances: []openstack.Instance{
					{
						Metadata:      trivyTypes.NewTestMetadata(),
						AdminPassword: trivyTypes.String("", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-OPNSTK-0002": {
		{
			name: "Firewall rule missing destination address",
			input: state.State{OpenStack: openstack.OpenStack{Compute: openstack.Compute{
				Firewall: openstack.Firewall{
					AllowRules: []openstack.FirewallRule{
						{
							Metadata:    trivyTypes.NewTestMetadata(),
							Enabled:     trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							Destination: trivyTypes.String("", trivyTypes.NewTestMetadata()),
							Source:      trivyTypes.String("10.10.10.1", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Firewall rule missing source address",
			input: state.State{OpenStack: openstack.OpenStack{Compute: openstack.Compute{
				Firewall: openstack.Firewall{
					AllowRules: []openstack.FirewallRule{
						{
							Metadata:    trivyTypes.NewTestMetadata(),
							Enabled:     trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							Destination: trivyTypes.String("10.10.10.2", trivyTypes.NewTestMetadata()),
							Source:      trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Firewall rule with public destination and source addresses",
			input: state.State{OpenStack: openstack.OpenStack{Compute: openstack.Compute{
				Firewall: openstack.Firewall{
					AllowRules: []openstack.FirewallRule{
						{
							Metadata:    trivyTypes.NewTestMetadata(),
							Enabled:     trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							Destination: trivyTypes.String("0.0.0.0", trivyTypes.NewTestMetadata()),
							Source:      trivyTypes.String("0.0.0.0", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Firewall rule with private destination and source addresses",
			input: state.State{OpenStack: openstack.OpenStack{Compute: openstack.Compute{
				Firewall: openstack.Firewall{
					AllowRules: []openstack.FirewallRule{
						{
							Metadata:    trivyTypes.NewTestMetadata(),
							Enabled:     trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							Destination: trivyTypes.String("10.10.10.1", trivyTypes.NewTestMetadata()),
							Source:      trivyTypes.String("10.10.10.2", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-OPNSTK-0005": {
		{
			name: "Security group missing description",
			input: state.State{OpenStack: openstack.OpenStack{Networking: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata:    trivyTypes.NewTestMetadata(),
						Description: trivyTypes.String("", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Security group with description",
			input: state.State{OpenStack: openstack.OpenStack{Networking: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata:    trivyTypes.NewTestMetadata(),
						Description: trivyTypes.String("this is for connecting to the database", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-OPNSTK-0004": {
		{
			name: "Security group rule missing address",
			input: state.State{OpenStack: openstack.OpenStack{Networking: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								IsIngress: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								CIDR:      trivyTypes.String("", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Security group rule with private address",
			input: state.State{OpenStack: openstack.OpenStack{Networking: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								IsIngress: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								CIDR:      trivyTypes.String("10.10.0.1", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Security group rule with single public address",
			input: state.State{OpenStack: openstack.OpenStack{Networking: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								IsIngress: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								CIDR:      trivyTypes.String("8.8.8.8", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Security group rule with large public cidr",
			input: state.State{OpenStack: openstack.OpenStack{Networking: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								IsIngress: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								CIDR:      trivyTypes.String("80.0.0.0/8", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
	},
	"AVD-OPNSTK-0003": {
		{
			name: "Security group rule missing address",
			input: state.State{OpenStack: openstack.OpenStack{Networking: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								IsIngress: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								CIDR:      trivyTypes.String("", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Security group rule with private address",
			input: state.State{OpenStack: openstack.OpenStack{Networking: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								IsIngress: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								CIDR:      trivyTypes.String("10.10.0.1", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Security group rule with single public address",
			input: state.State{OpenStack: openstack.OpenStack{Networking: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								IsIngress: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								CIDR:      trivyTypes.String("8.8.8.8", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Security group rule with large public cidr",
			input: state.State{OpenStack: openstack.OpenStack{Networking: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								IsIngress: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								CIDR:      trivyTypes.String("80.0.0.0/8", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
	},
}
