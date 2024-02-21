package securitycenter

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/securitycenter"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableStandardSubscription(t *testing.T) {
	tests := []struct {
		name     string
		input    securitycenter.SecurityCenter
		expected bool
	}{
		{
			name: "Security center set with free subscription",
			input: securitycenter.SecurityCenter{
				Subscriptions: []securitycenter.SubscriptionPricing{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Tier:     trivyTypes.String(securitycenter.TierFree, trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Security center set with standard subscription",
			input: securitycenter.SecurityCenter{
				Subscriptions: []securitycenter.SubscriptionPricing{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Tier:     trivyTypes.String(securitycenter.TierStandard, trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Azure.SecurityCenter = test.input
			results := CheckEnableStandardSubscription.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableStandardSubscription.LongID() {
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
