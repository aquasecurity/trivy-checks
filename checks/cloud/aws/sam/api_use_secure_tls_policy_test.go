package sam

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/sam"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckApiUseSecureTlsPolicy(t *testing.T) {
	tests := []struct {
		name     string
		input    sam.SAM
		expected bool
	}{
		{
			name: "SAM API TLS v1.0",
			input: sam.SAM{
				APIs: []sam.API{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						DomainConfiguration: sam.DomainConfiguration{
							Metadata:       trivyTypes.NewTestMetadata(),
							SecurityPolicy: trivyTypes.String("TLS_1_0", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "SAM API TLS v1.2",
			input: sam.SAM{
				APIs: []sam.API{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						DomainConfiguration: sam.DomainConfiguration{
							Metadata:       trivyTypes.NewTestMetadata(),
							SecurityPolicy: trivyTypes.String("TLS_1_2", trivyTypes.NewTestMetadata()),
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
			testState.AWS.SAM = test.input
			results := CheckApiUseSecureTlsPolicy.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckApiUseSecureTlsPolicy.LongID() {
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
