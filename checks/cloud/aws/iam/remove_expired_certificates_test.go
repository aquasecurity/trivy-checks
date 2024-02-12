package iam

import (
	"testing"
	"time"

	"github.com/aquasecurity/trivy/pkg/iac/state"
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckRemoveExpiredCertificates(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name:     "No certs",
			input:    iam.IAM{},
			expected: false,
		},
		{
			name: "Valid cert",
			input: iam.IAM{
				ServerCertificates: []iam.ServerCertificate{
					{
						Metadata:   defsecTypes.NewTestMetadata(),
						Expiration: defsecTypes.Time(time.Now().Add(time.Hour), defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "Expired cert",
			input: iam.IAM{
				ServerCertificates: []iam.ServerCertificate{
					{
						Metadata:   defsecTypes.NewTestMetadata(),
						Expiration: defsecTypes.Time(time.Now().Add(-time.Hour), defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.IAM = test.input
			results := CheckRemoveExpiredCertificates.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckRemoveExpiredCertificates.LongID() {
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
