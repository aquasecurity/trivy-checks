package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud"
	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/nas"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(nifcloudNasTestCases)
}

var nifcloudNasTestCases = testCases{
	"AVD-NIF-0015": {
		{
			name: "NIFCLOUD nas security group with no description provided",
			input: state.State{Nifcloud: nifcloud.Nifcloud{NAS: nas.NAS{
				NASSecurityGroups: []nas.NASSecurityGroup{
					{
						Metadata:    trivyTypes.NewTestMetadata(),
						Description: trivyTypes.String("", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD nas security group with default description",
			input: state.State{Nifcloud: nifcloud.Nifcloud{NAS: nas.NAS{
				NASSecurityGroups: []nas.NASSecurityGroup{
					{
						Metadata:    trivyTypes.NewTestMetadata(),
						Description: trivyTypes.String("Managed by Terraform", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD nas security group with proper description",
			input: state.State{Nifcloud: nifcloud.Nifcloud{NAS: nas.NAS{
				NASSecurityGroups: []nas.NASSecurityGroup{
					{
						Metadata:    trivyTypes.NewTestMetadata(),
						Description: trivyTypes.String("some proper description", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-NIF-0013": {
		{
			name: "NIFCLOUD nas instance with common private",
			input: state.State{Nifcloud: nifcloud.Nifcloud{NAS: nas.NAS{
				NASInstances: []nas.NASInstance{
					{
						Metadata:  trivyTypes.NewTestMetadata(),
						NetworkID: trivyTypes.String("net-COMMON_PRIVATE", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD nas instance with private LAN",
			input: state.State{Nifcloud: nifcloud.Nifcloud{NAS: nas.NAS{
				NASInstances: []nas.NASInstance{
					{
						Metadata:  trivyTypes.NewTestMetadata(),
						NetworkID: trivyTypes.String("net-some-private-lan", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-NIF-0014": {
		{
			name: "NIFCLOUD ingress nas security group rule with wildcard address",
			input: state.State{Nifcloud: nifcloud.Nifcloud{NAS: nas.NAS{
				NASSecurityGroups: []nas.NASSecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						CIDRs: []trivyTypes.StringValue{
							trivyTypes.String("0.0.0.0/0", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD ingress nas security group rule with private address",
			input: state.State{Nifcloud: nifcloud.Nifcloud{NAS: nas.NAS{
				NASSecurityGroups: []nas.NASSecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						CIDRs: []trivyTypes.StringValue{
							trivyTypes.String("10.0.0.0/16", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
