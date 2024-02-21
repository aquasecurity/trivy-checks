package sqs

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/sqs"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableQueueEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    sqs.SQS
		expected bool
	}{
		{
			name: "SQS Queue unencrypted",
			input: sqs.SQS{
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
			},
			expected: true,
		},
		{
			name: "SQS Queue encrypted with default key",
			input: sqs.SQS{
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
			},
			expected: false,
		},
		{
			name: "SQS Queue encrypted with proper key",
			input: sqs.SQS{
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
			},
			expected: false,
		},
		{
			name: "SQS Queue encrypted with proper key",
			input: sqs.SQS{
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
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.SQS = test.input
			results := CheckEnableQueueEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableQueueEncryption.LongID() {
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
