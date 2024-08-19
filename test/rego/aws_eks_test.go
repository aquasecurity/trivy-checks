package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/eks"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

var awsEksTestCases = testCases{
	"AVD-AWS-0038": {
		{
			name: "EKS cluster with all cluster logging disabled",
			input: state.State{AWS: aws.AWS{EKS: eks.EKS{
				Clusters: []eks.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Logging: eks.Logging{
							API:               trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							Audit:             trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							Authenticator:     trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							ControllerManager: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							Scheduler:         trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "EKS cluster with only some cluster logging enabled",
			input: state.State{AWS: aws.AWS{EKS: eks.EKS{
				Clusters: []eks.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Logging: eks.Logging{
							API:               trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							Audit:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							Authenticator:     trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							ControllerManager: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							Scheduler:         trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "EKS cluster with all cluster logging enabled",
			input: state.State{AWS: aws.AWS{EKS: eks.EKS{
				Clusters: []eks.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Logging: eks.Logging{
							API:               trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							Audit:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							Authenticator:     trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							ControllerManager: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							Scheduler:         trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0039": {
		{
			name: "EKS Cluster with no secrets in the resources attribute",
			input: state.State{AWS: aws.AWS{EKS: eks.EKS{
				Clusters: []eks.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: eks.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							Secrets:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							KMSKeyID: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "EKS Cluster with secrets in the resources attribute but no KMS key",
			input: state.State{AWS: aws.AWS{EKS: eks.EKS{
				Clusters: []eks.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: eks.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							Secrets:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							KMSKeyID: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "EKS Cluster with secrets in the resources attribute and a KMS key",
			input: state.State{AWS: aws.AWS{EKS: eks.EKS{
				Clusters: []eks.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: eks.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							Secrets:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							KMSKeyID: trivyTypes.String("some-arn", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0040": {
		{
			name: "EKS Cluster with public access enabled",
			input: state.State{AWS: aws.AWS{EKS: eks.EKS{
				Clusters: []eks.Cluster{
					{
						PublicAccessEnabled: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "EKS Cluster with public access disabled",
			input: state.State{AWS: aws.AWS{EKS: eks.EKS{
				Clusters: []eks.Cluster{
					{
						PublicAccessEnabled: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
