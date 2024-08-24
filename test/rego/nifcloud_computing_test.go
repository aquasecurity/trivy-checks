package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud"
	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/computing"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(nifcloudComputingTestCases)
}

var nifcloudComputingTestCases = testCases{
	"AVD-NIF-0003": {
		{
			name: "NIFCLOUD security group rule has no description",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Computing: computing.Computing{
				SecurityGroups: []computing.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						IngressRules: []computing.SecurityGroupRule{
							{
								Metadata:    trivyTypes.NewTestMetadata(),
								Description: trivyTypes.String("", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD security group rule has description",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Computing: computing.Computing{
				SecurityGroups: []computing.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						IngressRules: []computing.SecurityGroupRule{
							{
								Metadata:    trivyTypes.NewTestMetadata(),
								Description: trivyTypes.String("some description", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-NIF-0002": {
		{
			name: "NIFCLOUD security group with no description provided",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Computing: computing.Computing{
				SecurityGroups: []computing.SecurityGroup{
					{
						Metadata:    trivyTypes.NewTestMetadata(),
						Description: trivyTypes.String("", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD security group with default description",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Computing: computing.Computing{
				SecurityGroups: []computing.SecurityGroup{
					{
						Metadata:    trivyTypes.NewTestMetadata(),
						Description: trivyTypes.String("Managed by Terraform", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD security group with proper description",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Computing: computing.Computing{
				SecurityGroups: []computing.SecurityGroup{
					{
						Metadata:    trivyTypes.NewTestMetadata(),
						Description: trivyTypes.String("some proper description", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-NIF-0004": {
		{
			name: "NIFCLOUD instance with no security group provided",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Computing: computing.Computing{
				Instances: []computing.Instance{
					{
						Metadata:      trivyTypes.NewTestMetadata(),
						SecurityGroup: trivyTypes.String("", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD instance with security group",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Computing: computing.Computing{
				Instances: []computing.Instance{
					{
						Metadata:      trivyTypes.NewTestMetadata(),
						SecurityGroup: trivyTypes.String("some security group", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-NIF-0005": {
		{
			name: "NIFCLOUD instance with common private",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Computing: computing.Computing{
				Instances: []computing.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NetworkInterfaces: []computing.NetworkInterface{
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
			name: "NIFCLOUD instance with private LAN",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Computing: computing.Computing{
				Instances: []computing.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NetworkInterfaces: []computing.NetworkInterface{
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
	"AVD-NIF-0001": {
		{
			name: "NIFCLOUD ingress security group rule with wildcard address",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Computing: computing.Computing{
				SecurityGroups: []computing.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						IngressRules: []computing.SecurityGroupRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								CIDR:     trivyTypes.String("0.0.0.0/0", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD ingress security group rule with private address",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Computing: computing.Computing{
				SecurityGroups: []computing.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						IngressRules: []computing.SecurityGroupRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								CIDR:     trivyTypes.String("10.0.0.0/16", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
