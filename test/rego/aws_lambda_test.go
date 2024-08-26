package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/lambda"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(awsLambdaTestCases)
}

var awsLambdaTestCases = testCases{
	"AVD-AWS-0066": {
		{
			name: "Lambda function with no tracing mode specified",
			input: state.State{AWS: aws.AWS{Lambda: lambda.Lambda{
				Functions: []lambda.Function{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Tracing: lambda.Tracing{
							Metadata: trivyTypes.NewTestMetadata(),
							Mode:     trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Lambda function with active tracing mode",
			input: state.State{AWS: aws.AWS{Lambda: lambda.Lambda{
				Functions: []lambda.Function{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Tracing: lambda.Tracing{
							Metadata: trivyTypes.NewTestMetadata(),
							Mode:     trivyTypes.String(lambda.TracingModeActive, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0067": {
		{
			name: "Lambda function permission missing source ARN",
			input: state.State{AWS: aws.AWS{Lambda: lambda.Lambda{
				Functions: []lambda.Function{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Permissions: []lambda.Permission{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								Principal: trivyTypes.String("sns.amazonaws.com", trivyTypes.NewTestMetadata()),
								SourceARN: trivyTypes.String("", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Lambda function permission with source ARN",
			input: state.State{AWS: aws.AWS{Lambda: lambda.Lambda{
				Functions: []lambda.Function{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Permissions: []lambda.Permission{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								Principal: trivyTypes.String("sns.amazonaws.com", trivyTypes.NewTestMetadata()),
								SourceARN: trivyTypes.String("source-arn", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
