package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/neptune"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(awsNeptuneTestCases)
}

var awsNeptuneTestCases = testCases{
	"AVD-AWS-0075": {
		{
			name: "Neptune Cluster with audit logging disabled",
			input: state.State{AWS: aws.AWS{Neptune: neptune.Neptune{
				Clusters: []neptune.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Logging: neptune.Logging{
							Metadata: trivyTypes.NewTestMetadata(),
							Audit:    trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Neptune Cluster with audit logging enabled",
			input: state.State{AWS: aws.AWS{Neptune: neptune.Neptune{
				Clusters: []neptune.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Logging: neptune.Logging{
							Metadata: trivyTypes.NewTestMetadata(),
							Audit:    trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0076": {
		{
			name: "Neptune Cluster without storage encryption",
			input: state.State{AWS: aws.AWS{Neptune: neptune.Neptune{
				Clusters: []neptune.Cluster{
					{
						Metadata:         trivyTypes.NewTestMetadata(),
						StorageEncrypted: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Neptune Cluster with storage encryption",
			input: state.State{AWS: aws.AWS{Neptune: neptune.Neptune{
				Clusters: []neptune.Cluster{
					{
						Metadata:         trivyTypes.NewTestMetadata(),
						StorageEncrypted: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0128": {
		{
			name: "Neptune Cluster missing KMS key",
			input: state.State{AWS: aws.AWS{Neptune: neptune.Neptune{
				Clusters: []neptune.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						KMSKeyID: trivyTypes.String("", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Neptune Cluster encrypted with KMS key",
			input: state.State{AWS: aws.AWS{Neptune: neptune.Neptune{
				Clusters: []neptune.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						KMSKeyID: trivyTypes.String("some-kms-key", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
