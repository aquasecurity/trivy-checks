package compute

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/digitalocean/compute"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckUseSshKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Droplet missing SSH keys",
			input: compute.Compute{
				Droplets: []compute.Droplet{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						SSHKeys:  []trivyTypes.StringValue{},
					},
				},
			},
			expected: true,
		},
		{
			name: "Droplet with an SSH key provided",
			input: compute.Compute{
				Droplets: []compute.Droplet{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						SSHKeys: []trivyTypes.StringValue{
							trivyTypes.String("my-ssh-key", trivyTypes.NewTestMetadata()),
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
			testState.DigitalOcean.Compute = test.input
			results := CheckUseSshKeys.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckUseSshKeys.LongID() {
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
