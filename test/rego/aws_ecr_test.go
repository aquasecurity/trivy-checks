package test

import (
	"github.com/aquasecurity/iamgo"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ecr"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(awsEcrTestCases)
}

var awsEcrTestCases = testCases{
	"AVD-AWS-0030": {
		{
			name: "ECR repository with image scans disabled",
			input: state.State{AWS: aws.AWS{ECR: ecr.ECR{
				Repositories: []ecr.Repository{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ImageScanning: ecr.ImageScanning{
							Metadata:   trivyTypes.NewTestMetadata(),
							ScanOnPush: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "ECR repository with image scans enabled",
			input: state.State{AWS: aws.AWS{ECR: ecr.ECR{
				Repositories: []ecr.Repository{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ImageScanning: ecr.ImageScanning{
							Metadata:   trivyTypes.NewTestMetadata(),
							ScanOnPush: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0031": {
		{
			name: "ECR mutable image tags",
			input: state.State{AWS: aws.AWS{ECR: ecr.ECR{
				Repositories: []ecr.Repository{
					{
						Metadata:           trivyTypes.NewTestMetadata(),
						ImageTagsImmutable: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "ECR immutable image tags",
			input: state.State{AWS: aws.AWS{ECR: ecr.ECR{
				Repositories: []ecr.Repository{
					{
						Metadata:           trivyTypes.NewTestMetadata(),
						ImageTagsImmutable: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0032": {
		{
			name: "ECR repository policy with wildcard principal",
			input: state.State{AWS: aws.AWS{ECR: ecr.ECR{
				Repositories: []ecr.Repository{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Policies: func() []iam.Policy {

							sb := iamgo.NewStatementBuilder()
							sb.WithSid("new policy")
							sb.WithEffect("Allow")
							sb.WithAllPrincipals(true)
							sb.WithActions([]string{
								"ecr:GetDownloadUrlForLayer",
								"ecr:BatchGetImage",
								"ecr:BatchCheckLayerAvailability",
								"ecr:PutImage",
								"ecr:InitiateLayerUpload",
								"ecr:UploadLayerPart",
								"ecr:CompleteLayerUpload",
								"ecr:DescribeRepositories",
								"ecr:GetRepositoryPolicy",
								"ecr:ListImages",
								"ecr:DeleteRepository",
								"ecr:BatchDeleteImage",
								"ecr:SetRepositoryPolicy",
								"ecr:DeleteRepositoryPolicy",
							})

							builder := iamgo.NewPolicyBuilder()
							builder.WithVersion("2021-10-07")
							builder.WithStatement(sb.Build())

							return []iam.Policy{
								{
									Document: iam.Document{
										Metadata: trivyTypes.NewTestMetadata(),
										Parsed:   builder.Build(),
									},
								},
							}
						}(),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "ECR repository policy with specific principal",
			input: state.State{AWS: aws.AWS{ECR: ecr.ECR{
				Repositories: []ecr.Repository{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Policies: func() []iam.Policy {

							sb := iamgo.NewStatementBuilder()
							sb.WithSid("new policy")
							sb.WithEffect("Allow")
							sb.WithAWSPrincipals([]string{"arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"})
							sb.WithActions([]string{
								"ecr:GetDownloadUrlForLayer",
								"ecr:BatchGetImage",
								"ecr:BatchCheckLayerAvailability",
								"ecr:PutImage",
								"ecr:InitiateLayerUpload",
								"ecr:UploadLayerPart",
								"ecr:CompleteLayerUpload",
								"ecr:DescribeRepositories",
								"ecr:GetRepositoryPolicy",
								"ecr:ListImages",
								"ecr:DeleteRepository",
								"ecr:BatchDeleteImage",
								"ecr:SetRepositoryPolicy",
								"ecr:DeleteRepositoryPolicy",
							})

							builder := iamgo.NewPolicyBuilder()
							builder.WithVersion("2021-10-07")
							builder.WithStatement(sb.Build())

							return []iam.Policy{
								{
									Document: iam.Document{
										Metadata: trivyTypes.NewTestMetadata(),
										Parsed:   builder.Build(),
									},
								},
							}
						}(),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0033": {
		{
			name: "ECR repository not using KMS encryption",
			input: state.State{AWS: aws.AWS{ECR: ecr.ECR{
				Repositories: []ecr.Repository{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: ecr.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							Type:     trivyTypes.String(ecr.EncryptionTypeAES256, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "ECR repository using KMS encryption but missing key",
			input: state.State{AWS: aws.AWS{ECR: ecr.ECR{
				Repositories: []ecr.Repository{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: ecr.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							Type:     trivyTypes.String(ecr.EncryptionTypeKMS, trivyTypes.NewTestMetadata()),
							KMSKeyID: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "ECR repository encrypted with KMS key",
			input: state.State{AWS: aws.AWS{ECR: ecr.ECR{
				Repositories: []ecr.Repository{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: ecr.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							Type:     trivyTypes.String(ecr.EncryptionTypeKMS, trivyTypes.NewTestMetadata()),
							KMSKeyID: trivyTypes.String("some-kms-key", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
