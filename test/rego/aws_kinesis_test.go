package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/kinesis"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

var awsKinesisTestCases = testCases{
	"AVD-AWS-0064": {
		{
			name: "AWS Kinesis Stream with no encryption",
			input: state.State{AWS: aws.AWS{Kinesis: kinesis.Kinesis{
				Streams: []kinesis.Stream{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: kinesis.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							Type:     trivyTypes.String("NONE", trivyTypes.NewTestMetadata()),
							KMSKeyID: trivyTypes.String("some-key", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS Kinesis Stream with KMS encryption but no key",
			input: state.State{AWS: aws.AWS{Kinesis: kinesis.Kinesis{
				Streams: []kinesis.Stream{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: kinesis.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							Type:     trivyTypes.String(kinesis.EncryptionTypeKMS, trivyTypes.NewTestMetadata()),
							KMSKeyID: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS Kinesis Stream with KMS encryption and key",
			input: state.State{AWS: aws.AWS{Kinesis: kinesis.Kinesis{
				Streams: []kinesis.Stream{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: kinesis.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							Type:     trivyTypes.String(kinesis.EncryptionTypeKMS, trivyTypes.NewTestMetadata()),
							KMSKeyID: trivyTypes.String("some-key", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
