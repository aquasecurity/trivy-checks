package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud"
	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/rdb"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(nifcloudRdbTestCases)
}

var nifcloudRdbTestCases = testCases{
	"AVD-NIF-0012": {
		{
			name: "NIFCLOUD db security group with no description provided",
			input: state.State{Nifcloud: nifcloud.Nifcloud{RDB: rdb.RDB{
				DBSecurityGroups: []rdb.DBSecurityGroup{
					{
						Metadata:    trivyTypes.NewTestMetadata(),
						Description: trivyTypes.String("", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD db security group with default description",
			input: state.State{Nifcloud: nifcloud.Nifcloud{RDB: rdb.RDB{
				DBSecurityGroups: []rdb.DBSecurityGroup{
					{
						Metadata:    trivyTypes.NewTestMetadata(),
						Description: trivyTypes.String("Managed by Terraform", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD db security group with proper description",
			input: state.State{Nifcloud: nifcloud.Nifcloud{RDB: rdb.RDB{
				DBSecurityGroups: []rdb.DBSecurityGroup{
					{
						Metadata:    trivyTypes.NewTestMetadata(),
						Description: trivyTypes.String("some proper description", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-NIF-0010": {
		{
			name: "NIFCLOUD db instance with common private",
			input: state.State{Nifcloud: nifcloud.Nifcloud{RDB: rdb.RDB{
				DBInstances: []rdb.DBInstance{
					{
						Metadata:  trivyTypes.NewTestMetadata(),
						NetworkID: trivyTypes.String("net-COMMON_PRIVATE", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD db instance with private LAN",
			input: state.State{Nifcloud: nifcloud.Nifcloud{RDB: rdb.RDB{
				DBInstances: []rdb.DBInstance{
					{
						Metadata:  trivyTypes.NewTestMetadata(),
						NetworkID: trivyTypes.String("net-some-private-lan", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-NIF-0008": {
		{
			name: "RDB Instance with public access enabled",
			input: state.State{Nifcloud: nifcloud.Nifcloud{RDB: rdb.RDB{
				DBInstances: []rdb.DBInstance{
					{
						Metadata:     trivyTypes.NewTestMetadata(),
						PublicAccess: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "RDB Instance with public access disabled",
			input: state.State{Nifcloud: nifcloud.Nifcloud{RDB: rdb.RDB{
				DBInstances: []rdb.DBInstance{
					{
						Metadata:     trivyTypes.NewTestMetadata(),
						PublicAccess: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-NIF-0011": {
		{
			name: "NIFCLOUD ingress db security group rule with wildcard address",
			input: state.State{Nifcloud: nifcloud.Nifcloud{RDB: rdb.RDB{
				DBSecurityGroups: []rdb.DBSecurityGroup{
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
			name: "NIFCLOUD ingress db security group rule with private address",
			input: state.State{Nifcloud: nifcloud.Nifcloud{RDB: rdb.RDB{
				DBSecurityGroups: []rdb.DBSecurityGroup{
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
	"AVD-NIF-0009": {
		{
			name: "RDB Instance with 1 retention day (default)",
			input: state.State{Nifcloud: nifcloud.Nifcloud{RDB: rdb.RDB{
				DBInstances: []rdb.DBInstance{
					{
						Metadata:                  trivyTypes.NewTestMetadata(),
						BackupRetentionPeriodDays: trivyTypes.Int(1, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "RDB Instance with 5 retention days",
			input: state.State{Nifcloud: nifcloud.Nifcloud{RDB: rdb.RDB{
				DBInstances: []rdb.DBInstance{
					{
						Metadata:                  trivyTypes.NewTestMetadata(),
						BackupRetentionPeriodDays: trivyTypes.Int(5, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
