package apigateway

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	v1 "github.com/aquasecurity/trivy/pkg/iac/providers/aws/apigateway/v1"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicAccess(t *testing.T) {
	tests := []struct {
		name     string
		input    v1.APIGateway
		expected bool
	}{
		{
			name: "API GET method without authorization",
			input: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Resources: []v1.Resource{
							{
								Methods: []v1.Method{
									{
										Metadata:          trivyTypes.NewTestMetadata(),
										HTTPMethod:        trivyTypes.String("GET", trivyTypes.NewTestMetadata()),
										APIKeyRequired:    trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
										AuthorizationType: trivyTypes.String(v1.AuthorizationNone, trivyTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "API OPTION method without authorization",
			input: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Resources: []v1.Resource{
							{
								Methods: []v1.Method{
									{
										Metadata:          trivyTypes.NewTestMetadata(),
										HTTPMethod:        trivyTypes.String("OPTION", trivyTypes.NewTestMetadata()),
										APIKeyRequired:    trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
										AuthorizationType: trivyTypes.String(v1.AuthorizationNone, trivyTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "API GET method with IAM authorization",
			input: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Resources: []v1.Resource{
							{
								Methods: []v1.Method{
									{
										Metadata:          trivyTypes.NewTestMetadata(),
										HTTPMethod:        trivyTypes.String("GET", trivyTypes.NewTestMetadata()),
										APIKeyRequired:    trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
										AuthorizationType: trivyTypes.String(v1.AuthorizationIAM, trivyTypes.NewTestMetadata()),
									},
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
			testState.AWS.APIGateway.V1 = test.input
			results := CheckNoPublicAccess.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicAccess.LongID() {
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
