package network

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/network"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicIngress(t *testing.T) {
	tests := []struct {
		name     string
		input    network.Network
		expected bool
	}{
		{
			name: "Security group inbound rule with asterisk wildcard source address",
			input: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Allow:    trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								Outbound: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								SourceAddresses: []trivyTypes.StringValue{
									trivyTypes.String("*", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Security group inbound rule with lower case internet wildcard source address",
			input: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Allow:    trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								Outbound: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								SourceAddresses: []trivyTypes.StringValue{
									trivyTypes.String("internet", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Security group inbound rule with upper case internet wildcard source address",
			input: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Allow:    trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								Outbound: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								SourceAddresses: []trivyTypes.StringValue{
									trivyTypes.String("Internet", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Security group inbound rule with private source address",
			input: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Allow:    trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								Outbound: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								SourceAddresses: []trivyTypes.StringValue{
									trivyTypes.String("10.0.0.0/16", trivyTypes.NewTestMetadata()),
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
			testState.Azure.Network = test.input
			results := CheckNoPublicIngress.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicIngress.LongID() {
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
