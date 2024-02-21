package monitor

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/monitor"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckCaptureAllRegions(t *testing.T) {
	tests := []struct {
		name     string
		input    monitor.Monitor
		expected bool
	}{
		{
			name: "Log profile captures only eastern US region",
			input: monitor.Monitor{
				LogProfiles: []monitor.LogProfile{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Locations: []trivyTypes.StringValue{
							trivyTypes.String("eastus", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Log profile captures all regions",
			input: monitor.Monitor{
				LogProfiles: []monitor.LogProfile{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Locations: []trivyTypes.StringValue{
							trivyTypes.String("eastus", trivyTypes.NewTestMetadata()),
							trivyTypes.String("eastus2", trivyTypes.NewTestMetadata()),
							trivyTypes.String("southcentralus", trivyTypes.NewTestMetadata()),
							trivyTypes.String("westus2", trivyTypes.NewTestMetadata()),
							trivyTypes.String("westus3", trivyTypes.NewTestMetadata()),
							trivyTypes.String("australiaeast", trivyTypes.NewTestMetadata()),
							trivyTypes.String("southeastasia", trivyTypes.NewTestMetadata()),
							trivyTypes.String("northeurope", trivyTypes.NewTestMetadata()),
							trivyTypes.String("swedencentral", trivyTypes.NewTestMetadata()),
							trivyTypes.String("uksouth", trivyTypes.NewTestMetadata()),
							trivyTypes.String("westeurope", trivyTypes.NewTestMetadata()),
							trivyTypes.String("centralus", trivyTypes.NewTestMetadata()),
							trivyTypes.String("northcentralus", trivyTypes.NewTestMetadata()),
							trivyTypes.String("westus", trivyTypes.NewTestMetadata()),
							trivyTypes.String("southafricanorth", trivyTypes.NewTestMetadata()),
							trivyTypes.String("centralindia", trivyTypes.NewTestMetadata()),
							trivyTypes.String("eastasia", trivyTypes.NewTestMetadata()),
							trivyTypes.String("japaneast", trivyTypes.NewTestMetadata()),
							trivyTypes.String("jioindiawest", trivyTypes.NewTestMetadata()),
							trivyTypes.String("koreacentral", trivyTypes.NewTestMetadata()),
							trivyTypes.String("canadacentral", trivyTypes.NewTestMetadata()),
							trivyTypes.String("francecentral", trivyTypes.NewTestMetadata()),
							trivyTypes.String("germanywestcentral", trivyTypes.NewTestMetadata()),
							trivyTypes.String("norwayeast", trivyTypes.NewTestMetadata()),
							trivyTypes.String("switzerlandnorth", trivyTypes.NewTestMetadata()),
							trivyTypes.String("uaenorth", trivyTypes.NewTestMetadata()),
							trivyTypes.String("brazilsouth", trivyTypes.NewTestMetadata()),
							trivyTypes.String("centralusstage", trivyTypes.NewTestMetadata()),
							trivyTypes.String("eastusstage", trivyTypes.NewTestMetadata()),
							trivyTypes.String("eastus2stage", trivyTypes.NewTestMetadata()),
							trivyTypes.String("northcentralusstage", trivyTypes.NewTestMetadata()),
							trivyTypes.String("southcentralusstage", trivyTypes.NewTestMetadata()),
							trivyTypes.String("westusstage", trivyTypes.NewTestMetadata()),
							trivyTypes.String("westus2stage", trivyTypes.NewTestMetadata()),
							trivyTypes.String("asia", trivyTypes.NewTestMetadata()),
							trivyTypes.String("asiapacific", trivyTypes.NewTestMetadata()),
							trivyTypes.String("australia", trivyTypes.NewTestMetadata()),
							trivyTypes.String("brazil", trivyTypes.NewTestMetadata()),
							trivyTypes.String("canada", trivyTypes.NewTestMetadata()),
							trivyTypes.String("europe", trivyTypes.NewTestMetadata()),
							trivyTypes.String("global", trivyTypes.NewTestMetadata()),
							trivyTypes.String("india", trivyTypes.NewTestMetadata()),
							trivyTypes.String("japan", trivyTypes.NewTestMetadata()),
							trivyTypes.String("uk", trivyTypes.NewTestMetadata()),
							trivyTypes.String("unitedstates", trivyTypes.NewTestMetadata()),
							trivyTypes.String("eastasiastage", trivyTypes.NewTestMetadata()),
							trivyTypes.String("southeastasiastage", trivyTypes.NewTestMetadata()),
							trivyTypes.String("centraluseuap", trivyTypes.NewTestMetadata()),
							trivyTypes.String("eastus2euap", trivyTypes.NewTestMetadata()),
							trivyTypes.String("westcentralus", trivyTypes.NewTestMetadata()),
							trivyTypes.String("southafricawest", trivyTypes.NewTestMetadata()),
							trivyTypes.String("australiacentral", trivyTypes.NewTestMetadata()),
							trivyTypes.String("australiacentral2", trivyTypes.NewTestMetadata()),
							trivyTypes.String("australiasoutheast", trivyTypes.NewTestMetadata()),
							trivyTypes.String("japanwest", trivyTypes.NewTestMetadata()),
							trivyTypes.String("jioindiacentral", trivyTypes.NewTestMetadata()),
							trivyTypes.String("koreasouth", trivyTypes.NewTestMetadata()),
							trivyTypes.String("southindia", trivyTypes.NewTestMetadata()),
							trivyTypes.String("westindia", trivyTypes.NewTestMetadata()),
							trivyTypes.String("canadaeast", trivyTypes.NewTestMetadata()),
							trivyTypes.String("francesouth", trivyTypes.NewTestMetadata()),
							trivyTypes.String("germanynorth", trivyTypes.NewTestMetadata()),
							trivyTypes.String("norwaywest", trivyTypes.NewTestMetadata()),
							trivyTypes.String("swedensouth", trivyTypes.NewTestMetadata()),
							trivyTypes.String("switzerlandwest", trivyTypes.NewTestMetadata()),
							trivyTypes.String("ukwest", trivyTypes.NewTestMetadata()),
							trivyTypes.String("uaecentral", trivyTypes.NewTestMetadata()),
							trivyTypes.String("brazilsoutheast", trivyTypes.NewTestMetadata()),
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
			testState.Azure.Monitor = test.input
			results := CheckCaptureAllRegions.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckCaptureAllRegions.LongID() {
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
