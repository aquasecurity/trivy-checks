package cloudfront

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/cloudfront"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckUseSecureTlsPolicy(t *testing.T) {
	tests := []struct {
		name     string
		input    cloudfront.Cloudfront
		expected bool
	}{
		{
			name: "CloudFront distribution using TLS v1.0",
			input: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ViewerCertificate: cloudfront.ViewerCertificate{
							Metadata:               trivyTypes.NewTestMetadata(),
							MinimumProtocolVersion: trivyTypes.String("TLSv1.0", trivyTypes.NewTestMetadata()),
							SSLSupportMethod:       trivyTypes.String("sni-only", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "CloudFront distribution using TLS v1.2",
			input: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ViewerCertificate: cloudfront.ViewerCertificate{
							Metadata:               trivyTypes.NewTestMetadata(),
							MinimumProtocolVersion: trivyTypes.String(cloudfront.ProtocolVersionTLS1_2, trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "CloudFrontDefaultCertificate is true",
			input: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ViewerCertificate: cloudfront.ViewerCertificate{
							Metadata:                     trivyTypes.NewTestMetadata(),
							MinimumProtocolVersion:       trivyTypes.String("TLSv1.0", trivyTypes.NewTestMetadata()),
							CloudfrontDefaultCertificate: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "SSLSupportMethod is not `sny-only`",
			input: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ViewerCertificate: cloudfront.ViewerCertificate{
							Metadata:               trivyTypes.NewTestMetadata(),
							MinimumProtocolVersion: trivyTypes.String("TLSv1.0", trivyTypes.NewTestMetadata()),
							SSLSupportMethod:       trivyTypes.String("vip", trivyTypes.NewTestMetadata()),
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
			testState.AWS.Cloudfront = test.input
			results := CheckUseSecureTlsPolicy.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckUseSecureTlsPolicy.LongID() {
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
