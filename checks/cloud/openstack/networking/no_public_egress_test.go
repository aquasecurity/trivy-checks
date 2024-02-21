package compute

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/openstack"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicEgress(t *testing.T) {
	tests := []struct {
		name     string
		input    openstack.Networking
		expected bool
	}{
		{
			name: "Security group rule missing address",
			input: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								IsIngress: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								CIDR:      trivyTypes.String("", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Security group rule with private address",
			input: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								IsIngress: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								CIDR:      trivyTypes.String("10.10.0.1", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Security group rule with single public address",
			input: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								IsIngress: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								CIDR:      trivyTypes.String("8.8.8.8", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Security group rule with large public cidr",
			input: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								IsIngress: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								CIDR:      trivyTypes.String("80.0.0.0/8", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.OpenStack.Networking = test.input
			results := CheckNoPublicEgress.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicEgress.LongID() {
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
