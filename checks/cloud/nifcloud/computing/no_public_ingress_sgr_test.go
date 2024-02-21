package computing

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/computing"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicIngressSgr(t *testing.T) {
	tests := []struct {
		name     string
		input    computing.Computing
		expected bool
	}{
		{
			name: "NIFCLOUD ingress security group rule with wildcard address",
			input: computing.Computing{
				SecurityGroups: []computing.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						IngressRules: []computing.SecurityGroupRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								CIDR:     trivyTypes.String("0.0.0.0/0", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "NIFCLOUD ingress security group rule with private address",
			input: computing.Computing{
				SecurityGroups: []computing.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						IngressRules: []computing.SecurityGroupRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								CIDR:     trivyTypes.String("10.0.0.0/16", trivyTypes.NewTestMetadata()),
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
			testState.Nifcloud.Computing = test.input
			results := CheckNoPublicIngressSgr.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicIngressSgr.LongID() {
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
