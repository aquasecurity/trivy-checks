package test

import (
	"github.com/aquasecurity/iamgo"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/sqs"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(awsSqsTestCases)
}

var awsSqsTestCases = testCases{
	"AVD-AWS-0096": {
		{
			name: "SQS Queue unencrypted",
			input: state.State{AWS: aws.AWS{SQS: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: sqs.Encryption{
							Metadata:          trivyTypes.NewTestMetadata(),
							ManagedEncryption: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							KMSKeyID:          trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "SQS Queue encrypted with default key",
			input: state.State{AWS: aws.AWS{SQS: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: sqs.Encryption{
							Metadata:          trivyTypes.NewTestMetadata(),
							ManagedEncryption: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							KMSKeyID:          trivyTypes.String("alias/aws/sqs", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "SQS Queue encrypted with proper key",
			input: state.State{AWS: aws.AWS{SQS: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: sqs.Encryption{
							Metadata:          trivyTypes.NewTestMetadata(),
							ManagedEncryption: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							KMSKeyID:          trivyTypes.String("some-ok-key", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "SQS Queue encrypted with proper key",
			input: state.State{AWS: aws.AWS{SQS: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: sqs.Encryption{
							Metadata:          trivyTypes.NewTestMetadata(),
							ManagedEncryption: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							KMSKeyID:          trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0097": {
		{
			name: "AWS SQS policy document with wildcard action statement",
			input: state.State{AWS: aws.AWS{SQS: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Policies: func() []iam.Policy {

							sb := iamgo.NewStatementBuilder()
							sb.WithSid("new policy")
							sb.WithEffect("Allow")
							sb.WithActions([]string{
								"sqs:*",
							})
							sb.WithResources([]string{"arn:aws:sqs:::my-queue"})

							builder := iamgo.NewPolicyBuilder()
							builder.WithVersion("2012-10-17")
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
			name: "AWS SQS policy document with action statement list",
			input: state.State{AWS: aws.AWS{SQS: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Policies: func() []iam.Policy {

							sb := iamgo.NewStatementBuilder()
							sb.WithSid("new policy")
							sb.WithEffect("Allow")
							sb.WithActions([]string{
								"sqs:SendMessage",
								"sqs:ReceiveMessage",
							})
							sb.WithResources([]string{"arn:aws:sqs:::my-queue"})
							sb.WithAWSPrincipals([]string{"*"})

							builder := iamgo.NewPolicyBuilder()
							builder.WithVersion("2012-10-17")
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
	"AVD-AWS-0135": {
		{
			name: "SQS Queue unencrypted",
			input: state.State{AWS: aws.AWS{SQS: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: sqs.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							KMSKeyID: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "SQS Queue encrypted with default key",
			input: state.State{AWS: aws.AWS{SQS: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: sqs.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							KMSKeyID: trivyTypes.String("alias/aws/sqs", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "SQS Queue encrypted with proper key",
			input: state.State{AWS: aws.AWS{SQS: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: sqs.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							KMSKeyID: trivyTypes.String("some-ok-key", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
