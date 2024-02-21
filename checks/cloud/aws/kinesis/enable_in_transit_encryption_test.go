package kinesis

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/kinesis"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableInTransitEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    kinesis.Kinesis
		expected bool
	}{
		{
			name: "AWS Kinesis Stream with no encryption",
			input: kinesis.Kinesis{
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
			},
			expected: true,
		},
		{
			name: "AWS Kinesis Stream with KMS encryption but no key",
			input: kinesis.Kinesis{
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
			},
			expected: true,
		},
		{
			name: "AWS Kinesis Stream with KMS encryption and key",
			input: kinesis.Kinesis{
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
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.Kinesis = test.input
			results := CheckEnableInTransitEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableInTransitEncryption.LongID() {
					found = true
				}
			}
			if test.expected {
				assert.True(t, found, "Rule should have been found")
			} else {
				assert.False(t, found, "Rule should not have been found")
			}
		})
	}
}
