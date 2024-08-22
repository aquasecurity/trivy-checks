package network

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/network"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckDisableRdpFromInternet(t *testing.T) {
	tests := []struct {
		name     string
		input    network.Network
		expected bool
	}{
		{
			name: "Security group inbound rule allowing RDP access from the Internet",
			input: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Outbound: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								Allow:    trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								SourceAddresses: []trivyTypes.StringValue{
									trivyTypes.String("*", trivyTypes.NewTestMetadata()),
								},
								SourcePorts:          nil,
								DestinationAddresses: nil,
								DestinationPorts: []network.PortRange{
									{
										Metadata: trivyTypes.NewTestMetadata(),
										Start:    trivyTypes.IntTest(3310),
										End:      trivyTypes.IntTest(3390),
									},
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
			name: "Security group inbound rule allowing RDP access from a specific address",
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
										Start:    trivyTypes.IntTest(3310),
										End:      trivyTypes.IntTest(3390),
									},
								},
								SourceAddresses: []trivyTypes.StringValue{
									trivyTypes.String("4.53.160.75", trivyTypes.NewTestMetadata()),
								},
								Protocol: trivyTypes.String("Tcp", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Security group inbound rule allowing only ICMP",
			input: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Outbound: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								Allow:    trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								SourceAddresses: []trivyTypes.StringValue{
									trivyTypes.String("*", trivyTypes.NewTestMetadata()),
								},
								SourcePorts:          nil,
								DestinationAddresses: nil,
								DestinationPorts: []network.PortRange{
									{
										Metadata: trivyTypes.NewTestMetadata(),
										Start:    trivyTypes.IntTest(3310),
										End:      trivyTypes.IntTest(3390),
									},
								},
								Protocol: trivyTypes.String("Icmp", trivyTypes.NewTestMetadata()),
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
			results := CheckDisableRdpFromInternet.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckDisableRdpFromInternet.LongID() {
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
