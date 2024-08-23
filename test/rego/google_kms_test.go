package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/google"
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/kms"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(googleKmsTestCases)
}

var googleKmsTestCases = testCases{
	"AVD-GCP-0065": {
		{
			name: "KMS key rotation period of 91 days",
			input: state.State{Google: google.Google{KMS: kms.KMS{
				KeyRings: []kms.KeyRing{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Keys: []kms.Key{
							{
								Metadata:              trivyTypes.NewTestMetadata(),
								RotationPeriodSeconds: trivyTypes.Int(7862400, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "KMS key rotation period of 30 days",
			input: state.State{Google: google.Google{KMS: kms.KMS{
				KeyRings: []kms.KeyRing{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Keys: []kms.Key{
							{
								Metadata:              trivyTypes.NewTestMetadata(),
								RotationPeriodSeconds: trivyTypes.Int(2592000, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
