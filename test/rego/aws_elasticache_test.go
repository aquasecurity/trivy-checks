package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/elasticache"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

var awsElastiCacheTestCases = testCases{
	"AVD-AWS-0049": {
		{
			name: "ElastiCache security group with no description provided",
			input: state.State{AWS: aws.AWS{ElastiCache: elasticache.ElastiCache{
				SecurityGroups: []elasticache.SecurityGroup{
					{
						Metadata:    trivyTypes.NewTestMetadata(),
						Description: trivyTypes.String("", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "ElastiCache security group with description",
			input: state.State{AWS: aws.AWS{ElastiCache: elasticache.ElastiCache{
				SecurityGroups: []elasticache.SecurityGroup{
					{
						Metadata:    trivyTypes.NewTestMetadata(),
						Description: trivyTypes.String("some decent description", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0045": {
		{
			name: "ElastiCache replication group with at-rest encryption disabled",
			input: state.State{AWS: aws.AWS{ElastiCache: elasticache.ElastiCache{
				ReplicationGroups: []elasticache.ReplicationGroup{
					{
						Metadata:                trivyTypes.NewTestMetadata(),
						AtRestEncryptionEnabled: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "ElastiCache replication group with at-rest encryption enabled",
			input: state.State{AWS: aws.AWS{ElastiCache: elasticache.ElastiCache{
				ReplicationGroups: []elasticache.ReplicationGroup{
					{
						Metadata:                trivyTypes.NewTestMetadata(),
						AtRestEncryptionEnabled: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0050": {
		{
			name: "Cluster snapshot retention days set to 0",
			input: state.State{AWS: aws.AWS{ElastiCache: elasticache.ElastiCache{
				Clusters: []elasticache.Cluster{
					{
						Metadata:               trivyTypes.NewTestMetadata(),
						Engine:                 trivyTypes.String("redis", trivyTypes.NewTestMetadata()),
						NodeType:               trivyTypes.String("cache.m4.large", trivyTypes.NewTestMetadata()),
						SnapshotRetentionLimit: trivyTypes.Int(0, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster snapshot retention days set to 5",
			input: state.State{AWS: aws.AWS{ElastiCache: elasticache.ElastiCache{
				Clusters: []elasticache.Cluster{
					{
						Metadata:               trivyTypes.NewTestMetadata(),
						Engine:                 trivyTypes.String("redis", trivyTypes.NewTestMetadata()),
						NodeType:               trivyTypes.String("cache.m4.large", trivyTypes.NewTestMetadata()),
						SnapshotRetentionLimit: trivyTypes.Int(5, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0051": {
		{
			name: "ElastiCache replication group with in-transit encryption disabled",
			input: state.State{AWS: aws.AWS{ElastiCache: elasticache.ElastiCache{
				ReplicationGroups: []elasticache.ReplicationGroup{
					{
						Metadata:                 trivyTypes.NewTestMetadata(),
						TransitEncryptionEnabled: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "ElastiCache replication group with in-transit encryption enabled",
			input: state.State{AWS: aws.AWS{ElastiCache: elasticache.ElastiCache{
				ReplicationGroups: []elasticache.ReplicationGroup{
					{
						Metadata:                 trivyTypes.NewTestMetadata(),
						TransitEncryptionEnabled: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
