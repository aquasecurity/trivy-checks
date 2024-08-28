package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/rds"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(awsRdsTestCases)
}

var awsRdsTestCases = testCases{
	"AVD-AWS-0133": {
		{
			name: "RDS Instance with performance insights disabled",
			input: state.State{AWS: aws.AWS{RDS: rds.RDS{
				Instances: []rds.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						PerformanceInsights: rds.PerformanceInsights{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							KMSKeyID: trivyTypes.String("some-kms-key", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},

		{
			name: "RDS Instance with performance insights enabled and KMS key provided",
			input: state.State{AWS: aws.AWS{RDS: rds.RDS{
				Instances: []rds.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						PerformanceInsights: rds.PerformanceInsights{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							KMSKeyID: trivyTypes.String("some-kms-key", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0079": {
		{
			name: "RDS Cluster with storage encryption disabled",
			input: state.State{AWS: aws.AWS{RDS: rds.RDS{
				Clusters: []rds.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: rds.Encryption{
							Metadata:       trivyTypes.NewTestMetadata(),
							EncryptStorage: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							KMSKeyID:       trivyTypes.String("kms-key", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "RDS Cluster with storage encryption enabled but missing KMS key",
			input: state.State{AWS: aws.AWS{RDS: rds.RDS{
				Clusters: []rds.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: rds.Encryption{
							Metadata:       trivyTypes.NewTestMetadata(),
							EncryptStorage: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							KMSKeyID:       trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "RDS Cluster with storage encryption enabled and KMS key provided",
			input: state.State{AWS: aws.AWS{RDS: rds.RDS{
				Clusters: []rds.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: rds.Encryption{
							Metadata:       trivyTypes.NewTestMetadata(),
							EncryptStorage: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							KMSKeyID:       trivyTypes.String("kms-key", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0080": {
		{
			name: "RDS Instance with unencrypted storage",
			input: state.State{AWS: aws.AWS{RDS: rds.RDS{
				Instances: []rds.Instance{
					{
						Metadata:             trivyTypes.NewTestMetadata(),
						ReplicationSourceARN: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						Encryption: rds.Encryption{
							Metadata:       trivyTypes.NewTestMetadata(),
							EncryptStorage: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "RDS Instance with encrypted storage",
			input: state.State{AWS: aws.AWS{RDS: rds.RDS{
				Instances: []rds.Instance{
					{
						Metadata:             trivyTypes.NewTestMetadata(),
						ReplicationSourceARN: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						Encryption: rds.Encryption{
							Metadata:       trivyTypes.NewTestMetadata(),
							EncryptStorage: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0078": {
		{
			name: "RDS Instance with performance insights disabled",
			input: state.State{AWS: aws.AWS{RDS: rds.RDS{
				Instances: []rds.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						PerformanceInsights: rds.PerformanceInsights{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							KMSKeyID: trivyTypes.String("some-kms-key", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "RDS Cluster instance with performance insights enabled but missing KMS key",
			input: state.State{AWS: aws.AWS{RDS: rds.RDS{
				Clusters: []rds.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Instances: []rds.ClusterInstance{
							{
								Instance: rds.Instance{
									Metadata: trivyTypes.NewTestMetadata(),
									PerformanceInsights: rds.PerformanceInsights{
										Metadata: trivyTypes.NewTestMetadata(),
										Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
										KMSKeyID: trivyTypes.String("", trivyTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "RDS Instance with performance insights enabled and KMS key provided",
			input: state.State{AWS: aws.AWS{RDS: rds.RDS{
				Instances: []rds.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						PerformanceInsights: rds.PerformanceInsights{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							KMSKeyID: trivyTypes.String("some-kms-key", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0077": {
		{
			name: "RDS Cluster with 1 retention day (default)",
			input: state.State{AWS: aws.AWS{RDS: rds.RDS{
				Clusters: []rds.Cluster{
					{
						Metadata:                  trivyTypes.NewTestMetadata(),
						ReplicationSourceARN:      trivyTypes.String("", trivyTypes.NewTestMetadata()),
						BackupRetentionPeriodDays: trivyTypes.Int(1, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "RDS Instance with 1 retention day (default)",
			input: state.State{AWS: aws.AWS{RDS: rds.RDS{
				Instances: []rds.Instance{
					{
						Metadata:                  trivyTypes.NewTestMetadata(),
						ReplicationSourceARN:      trivyTypes.String("", trivyTypes.NewTestMetadata()),
						BackupRetentionPeriodDays: trivyTypes.Int(1, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "RDS Cluster with 5 retention days",
			input: state.State{AWS: aws.AWS{RDS: rds.RDS{
				Clusters: []rds.Cluster{
					{
						Metadata:                  trivyTypes.NewTestMetadata(),
						ReplicationSourceARN:      trivyTypes.String("", trivyTypes.NewTestMetadata()),
						BackupRetentionPeriodDays: trivyTypes.Int(5, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name: "RDS Instance with 5 retention days",
			input: state.State{AWS: aws.AWS{RDS: rds.RDS{
				Instances: []rds.Instance{
					{
						Metadata:                  trivyTypes.NewTestMetadata(),
						ReplicationSourceARN:      trivyTypes.String("", trivyTypes.NewTestMetadata()),
						BackupRetentionPeriodDays: trivyTypes.Int(5, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
