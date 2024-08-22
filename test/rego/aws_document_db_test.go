package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/documentdb"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(awsDocumentDBTestCases)
}

var awsDocumentDBTestCases = testCases{
	"AVD-AWS-0020": {
		{
			name: "DocDB Cluster not exporting logs",
			input: state.State{AWS: aws.AWS{DocumentDB: documentdb.DocumentDB{
				Clusters: []documentdb.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						EnabledLogExports: []trivyTypes.StringValue{
							trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "DocDB Cluster exporting audit logs",
			input: state.State{AWS: aws.AWS{DocumentDB: documentdb.DocumentDB{
				Clusters: []documentdb.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						EnabledLogExports: []trivyTypes.StringValue{
							trivyTypes.String(documentdb.LogExportAudit, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "DocDB Cluster exporting profiler logs",
			input: state.State{AWS: aws.AWS{DocumentDB: documentdb.DocumentDB{
				Clusters: []documentdb.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						EnabledLogExports: []trivyTypes.StringValue{
							trivyTypes.String(documentdb.LogExportProfiler, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0021": {
		{
			name: "DocDB unencrypted storage",
			input: state.State{AWS: aws.AWS{DocumentDB: documentdb.DocumentDB{
				Clusters: []documentdb.Cluster{
					{
						Metadata:         trivyTypes.NewTestMetadata(),
						StorageEncrypted: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "DocDB encrypted storage",
			input: state.State{AWS: aws.AWS{DocumentDB: documentdb.DocumentDB{
				Clusters: []documentdb.Cluster{
					{
						Metadata:         trivyTypes.NewTestMetadata(),
						StorageEncrypted: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0022": {
		{
			name: "DocDB Cluster encryption missing KMS key",
			input: state.State{AWS: aws.AWS{DocumentDB: documentdb.DocumentDB{
				Clusters: []documentdb.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						KMSKeyID: trivyTypes.String("", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "DocDB Instance encryption missing KMS key",
			input: state.State{AWS: aws.AWS{DocumentDB: documentdb.DocumentDB{
				Clusters: []documentdb.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						KMSKeyID: trivyTypes.String("kms-key", trivyTypes.NewTestMetadata()),
						Instances: []documentdb.Instance{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								KMSKeyID: trivyTypes.String("", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "DocDB Cluster and Instance encrypted with proper KMS keys",
			input: state.State{AWS: aws.AWS{DocumentDB: documentdb.DocumentDB{
				Clusters: []documentdb.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						KMSKeyID: trivyTypes.String("kms-key", trivyTypes.NewTestMetadata()),
						Instances: []documentdb.Instance{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								KMSKeyID: trivyTypes.String("kms-key", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
