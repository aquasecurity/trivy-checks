package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/sns"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(awsSnsTestCases)
}

var awsSnsTestCases = testCases{
	"AVD-AWS-0095": {
		{
			name: "AWS SNS Topic without encryption",
			input: state.State{AWS: aws.AWS{SNS: sns.SNS{
				Topics: []sns.Topic{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: sns.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							KMSKeyID: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS SNS Topic encrypted with default key",
			input: state.State{AWS: aws.AWS{SNS: sns.SNS{
				Topics: []sns.Topic{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: sns.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							KMSKeyID: trivyTypes.String("alias/aws/sns", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "AWS SNS Topic properly encrypted",
			input: state.State{AWS: aws.AWS{SNS: sns.SNS{
				Topics: []sns.Topic{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: sns.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							KMSKeyID: trivyTypes.String("some-ok-key", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0136": {
		{
			name: "AWS SNS Topic without encryption",
			input: state.State{AWS: aws.AWS{SNS: sns.SNS{
				Topics: []sns.Topic{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: sns.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							KMSKeyID: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "AWS SNS Topic encrypted with default key",
			input: state.State{AWS: aws.AWS{SNS: sns.SNS{
				Topics: []sns.Topic{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: sns.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							KMSKeyID: trivyTypes.String("alias/aws/sns", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS SNS Topic properly encrypted",
			input: state.State{AWS: aws.AWS{SNS: sns.SNS{
				Topics: []sns.Topic{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: sns.Encryption{
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
