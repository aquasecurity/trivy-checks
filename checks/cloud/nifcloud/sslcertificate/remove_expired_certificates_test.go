package sslcertificate

import (
	"testing"
	"time"

	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/sslcertificate"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckRemoveExpiredCertificates(t *testing.T) {
	tests := []struct {
		name     string
		input    sslcertificate.SSLCertificate
		expected bool
	}{
		{
			name:     "No certs",
			input:    sslcertificate.SSLCertificate{},
			expected: false,
		},
		{
			name: "Valid cert",
			input: sslcertificate.SSLCertificate{
				ServerCertificates: []sslcertificate.ServerCertificate{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Expiration: trivyTypes.Time(time.Now().Add(time.Hour), trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "Expired cert",
			input: sslcertificate.SSLCertificate{
				ServerCertificates: []sslcertificate.ServerCertificate{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Expiration: trivyTypes.Time(time.Now().Add(-time.Hour), trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Nifcloud.SSLCertificate = test.input
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
