package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/kms"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(awsKmsTestCases)
}

var awsKmsTestCases = testCases{
	"AVD-AWS-0065": {
		{
			name: "ENCRYPT_DECRYPT KMS Key with auto-rotation disabled",
			input: state.State{AWS: aws.AWS{KMS: kms.KMS{
				Keys: []kms.Key{
					{
						Usage:           trivyTypes.String("ENCRYPT_DECRYPT", trivyTypes.NewTestMetadata()),
						RotationEnabled: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "ENCRYPT_DECRYPT KMS Key with auto-rotation enabled",
			input: state.State{AWS: aws.AWS{KMS: kms.KMS{
				Keys: []kms.Key{
					{
						Usage:           trivyTypes.String("ENCRYPT_DECRYPT", trivyTypes.NewTestMetadata()),
						RotationEnabled: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name: "SIGN_VERIFY KMS Key with auto-rotation disabled",
			input: state.State{AWS: aws.AWS{KMS: kms.KMS{
				Keys: []kms.Key{
					{
						Usage:           trivyTypes.String(kms.KeyUsageSignAndVerify, trivyTypes.NewTestMetadata()),
						RotationEnabled: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
