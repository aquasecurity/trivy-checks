package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/dynamodb"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(awsDynamodbTestCases)
}

var awsDynamodbTestCases = testCases{
	"AVD-AWS-0023": {
		{
			name: "Cluster with SSE disabled",
			input: state.State{AWS: aws.AWS{DynamoDB: dynamodb.DynamoDB{
				DAXClusters: []dynamodb.DAXCluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ServerSideEncryption: dynamodb.ServerSideEncryption{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster with SSE enabled",
			input: state.State{AWS: aws.AWS{DynamoDB: dynamodb.DynamoDB{
				DAXClusters: []dynamodb.DAXCluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ServerSideEncryption: dynamodb.ServerSideEncryption{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0024": {
		{
			name: "Cluster with point in time recovery disabled",
			input: state.State{AWS: aws.AWS{DynamoDB: dynamodb.DynamoDB{
				DAXClusters: []dynamodb.DAXCluster{
					{
						Metadata:            trivyTypes.NewTestMetadata(),
						PointInTimeRecovery: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster with point in time recovery enabled",
			input: state.State{AWS: aws.AWS{DynamoDB: dynamodb.DynamoDB{
				DAXClusters: []dynamodb.DAXCluster{
					{
						Metadata:            trivyTypes.NewTestMetadata(),
						PointInTimeRecovery: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0025": {
		{
			name: "Cluster encryption missing KMS key",
			input: state.State{AWS: aws.AWS{DynamoDB: dynamodb.DynamoDB{
				Tables: []dynamodb.Table{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ServerSideEncryption: dynamodb.ServerSideEncryption{
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							Metadata: trivyTypes.NewTestMetadata(),
							KMSKeyID: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster encryption using default KMS key",
			input: state.State{AWS: aws.AWS{DynamoDB: dynamodb.DynamoDB{
				Tables: []dynamodb.Table{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ServerSideEncryption: dynamodb.ServerSideEncryption{
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							Metadata: trivyTypes.NewTestMetadata(),
							KMSKeyID: trivyTypes.String(dynamodb.DefaultKMSKeyID, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster encryption using proper KMS key",
			input: state.State{AWS: aws.AWS{DynamoDB: dynamodb.DynamoDB{
				Tables: []dynamodb.Table{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ServerSideEncryption: dynamodb.ServerSideEncryption{
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							Metadata: trivyTypes.NewTestMetadata(),
							KMSKeyID: trivyTypes.String("some-ok-key", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "KMS key exist, but SSE is not enabled",
			input: state.State{AWS: aws.AWS{DynamoDB: dynamodb.DynamoDB{
				Tables: []dynamodb.Table{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ServerSideEncryption: dynamodb.ServerSideEncryption{
							Enabled:  trivyTypes.BoolDefault(false, trivyTypes.NewTestMetadata()),
							Metadata: trivyTypes.NewTestMetadata(),
							KMSKeyID: trivyTypes.String("some-ok-key", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
	},
}
