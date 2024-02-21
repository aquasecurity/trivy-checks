package network

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/network"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckSshBlockedFromInternet(t *testing.T) {
	tests := []struct {
		name     string
		input    network.Network
		expected bool
	}{
		{
			name: "Security group rule allowing SSH access from the public internet",
			input: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Allow:    trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								Outbound: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								DestinationPorts: []network.PortRange{
									{
										Metadata: trivyTypes.NewTestMetadata(),
										Start:    22,
										End:      22,
									},
								},
								SourceAddresses: []trivyTypes.StringValue{
									trivyTypes.String("*", trivyTypes.NewTestMetadata()),
								},
								Protocol: trivyTypes.String("Tcp", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Security group rule allowing SSH only ICMP",
			input: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Allow:    trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								Outbound: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								DestinationPorts: []network.PortRange{
									{
										Metadata: trivyTypes.NewTestMetadata(),
										Start:    22,
										End:      22,
									},
								},
								SourceAddresses: []trivyTypes.StringValue{
									trivyTypes.String("*", trivyTypes.NewTestMetadata()),
								},
								Protocol: trivyTypes.String("Icmp", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Security group rule allowing SSH access from a specific address",
			input: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Allow:    trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								Outbound: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								DestinationPorts: []network.PortRange{
									{
										Metadata: trivyTypes.NewTestMetadata(),
										Start:    22,
										End:      22,
									},
								},
								SourceAddresses: []trivyTypes.StringValue{
									trivyTypes.String("82.102.23.23", trivyTypes.NewTestMetadata()),
								},
								Protocol: trivyTypes.String("Tcp", trivyTypes.NewTestMetadata()),
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
			testState.Azure.Network = test.input
			results := CheckSshBlockedFromInternet.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckSshBlockedFromInternet.LongID() {
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
