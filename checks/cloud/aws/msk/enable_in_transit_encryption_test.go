package msk

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/msk"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableInTransitEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    msk.MSK
		expected bool
	}{
		{
			name: "Cluster client broker with plaintext encryption",
			input: msk.MSK{
				Clusters: []msk.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						EncryptionInTransit: msk.EncryptionInTransit{
							Metadata:     trivyTypes.NewTestMetadata(),
							ClientBroker: trivyTypes.String(msk.ClientBrokerEncryptionPlaintext, trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster client broker with plaintext or TLS encryption",
			input: msk.MSK{
				Clusters: []msk.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						EncryptionInTransit: msk.EncryptionInTransit{
							Metadata:     trivyTypes.NewTestMetadata(),
							ClientBroker: trivyTypes.String(msk.ClientBrokerEncryptionTLSOrPlaintext, trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster client broker with TLS encryption",
			input: msk.MSK{
				Clusters: []msk.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						EncryptionInTransit: msk.EncryptionInTransit{
							Metadata:     trivyTypes.NewTestMetadata(),
							ClientBroker: trivyTypes.String(msk.ClientBrokerEncryptionTLS, trivyTypes.NewTestMetadata()),
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
			testState.AWS.MSK = test.input
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
