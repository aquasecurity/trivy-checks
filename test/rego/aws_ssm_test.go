package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ssm"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

var awsSsmTestCases = testCases{
	"AVD-AWS-0098": {
		{
			name: "AWS SSM missing KMS key",
			input: state.State{AWS: aws.AWS{SSM: ssm.SSM{
				Secrets: []ssm.Secret{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						KMSKeyID: trivyTypes.String("", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS SSM with default KMS key",
			input: state.State{AWS: aws.AWS{SSM: ssm.SSM{
				Secrets: []ssm.Secret{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						KMSKeyID: trivyTypes.String(ssm.DefaultKMSKeyID, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS SSM with proper KMS key",
			input: state.State{AWS: aws.AWS{SSM: ssm.SSM{
				Secrets: []ssm.Secret{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						KMSKeyID: trivyTypes.String("some-ok-key", trivyTypes.NewTestMetadata()),
					},
				}}},
			},
			expected: false,
		},
	},
}
