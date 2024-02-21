package cloudfront

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/cloudfront"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnforceHttps(t *testing.T) {
	tests := []struct {
		name     string
		input    cloudfront.Cloudfront
		expected bool
	}{
		{
			name: "CloudFront distribution default cache behaviour with allow all policy",
			input: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						DefaultCacheBehaviour: cloudfront.CacheBehaviour{
							Metadata:             trivyTypes.NewTestMetadata(),
							ViewerProtocolPolicy: trivyTypes.String(cloudfront.ViewerPolicyProtocolAllowAll, trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "CloudFront distribution ordered cache behaviour with allow all policy",
			input: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						DefaultCacheBehaviour: cloudfront.CacheBehaviour{
							Metadata:             trivyTypes.NewTestMetadata(),
							ViewerProtocolPolicy: trivyTypes.String(cloudfront.ViewerPolicyProtocolHTTPSOnly, trivyTypes.NewTestMetadata()),
						},
						OrdererCacheBehaviours: []cloudfront.CacheBehaviour{
							{
								Metadata:             trivyTypes.NewTestMetadata(),
								ViewerProtocolPolicy: trivyTypes.String(cloudfront.ViewerPolicyProtocolAllowAll, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "CloudFront distribution cache behaviours allowing HTTPS only",
			input: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						DefaultCacheBehaviour: cloudfront.CacheBehaviour{
							Metadata:             trivyTypes.NewTestMetadata(),
							ViewerProtocolPolicy: trivyTypes.String(cloudfront.ViewerPolicyProtocolHTTPSOnly, trivyTypes.NewTestMetadata()),
						},
						OrdererCacheBehaviours: []cloudfront.CacheBehaviour{
							{
								Metadata:             trivyTypes.NewTestMetadata(),
								ViewerProtocolPolicy: trivyTypes.String(cloudfront.ViewerPolicyProtocolHTTPSOnly, trivyTypes.NewTestMetadata()),
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
			testState.AWS.Cloudfront = test.input
			results := CheckEnforceHttps.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnforceHttps.LongID() {
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
