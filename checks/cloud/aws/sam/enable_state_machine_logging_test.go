package sam

import (
	"testing"

	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/sam"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableStateMachineLogging(t *testing.T) {
	tests := []struct {
		name     string
		input    sam.SAM
		expected bool
	}{
		{
			name: "State machine logging disabled",
			input: sam.SAM{
				StateMachines: []sam.StateMachine{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						LoggingConfiguration: sam.LoggingConfiguration{
							Metadata:       defsecTypes.NewTestMetadata(),
							LoggingEnabled: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "State machine logging enabled",
			input: sam.SAM{
				StateMachines: []sam.StateMachine{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						LoggingConfiguration: sam.LoggingConfiguration{
							Metadata:       defsecTypes.NewTestMetadata(),
							LoggingEnabled: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
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
			results := CheckEnableStateMachineLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableStateMachineLogging.LongID() {
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
