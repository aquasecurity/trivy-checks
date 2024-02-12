package dns

import (
	"testing"

	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/dns"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoRsaSha1(t *testing.T) {
	tests := []struct {
		name     string
		input    dns.DNS
		expected bool
	}{
		{
			name: "Zone signing using RSA SHA1 key",
			input: dns.DNS{
				ManagedZones: []dns.ManagedZone{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						DNSSec: dns.DNSSec{
							Metadata: defsecTypes.NewTestMetadata(),
							DefaultKeySpecs: []dns.KeySpecs{
								{
									Metadata:  defsecTypes.NewTestMetadata(),
									Algorithm: defsecTypes.String("rsasha1", defsecTypes.NewTestMetadata()),
									KeyType:   defsecTypes.String("keySigning", defsecTypes.NewTestMetadata()),
								},
								{
									Metadata:  defsecTypes.NewTestMetadata(),
									Algorithm: defsecTypes.String("rsasha1", defsecTypes.NewTestMetadata()),
									KeyType:   defsecTypes.String("zoneSigning", defsecTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Zone signing using RSA SHA512 key",
			input: dns.DNS{
				ManagedZones: []dns.ManagedZone{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						DNSSec: dns.DNSSec{
							Metadata: defsecTypes.NewTestMetadata(),
							DefaultKeySpecs: []dns.KeySpecs{
								{
									Metadata:  defsecTypes.NewTestMetadata(),
									Algorithm: defsecTypes.String("rsasha512", defsecTypes.NewTestMetadata()),
									KeyType:   defsecTypes.String("keySigning", defsecTypes.NewTestMetadata()),
								},
								{
									Metadata:  defsecTypes.NewTestMetadata(),
									Algorithm: defsecTypes.String("rsasha512", defsecTypes.NewTestMetadata()),
									KeyType:   defsecTypes.String("zoneSigning", defsecTypes.NewTestMetadata()),
								},
							},
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
			testState.Google.DNS = test.input
			results := CheckNoRsaSha1.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoRsaSha1.LongID() {
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
