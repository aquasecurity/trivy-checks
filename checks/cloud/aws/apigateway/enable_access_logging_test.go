package apigateway

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	v1 "github.com/aquasecurity/trivy/pkg/iac/providers/aws/apigateway/v1"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableAccessLogging(t *testing.T) {
	tests := []struct {
		name     string
		input    v1.APIGateway
		expected bool
	}{
		{
			name: "API Gateway stage with no log group ARN",
			input: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Stages: []v1.Stage{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								AccessLogging: v1.AccessLogging{
									Metadata:              trivyTypes.NewTestMetadata(),
									CloudwatchLogGroupARN: trivyTypes.String("", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "API Gateway stage with log group ARN",
			input: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Stages: []v1.Stage{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								AccessLogging: v1.AccessLogging{
									Metadata:              trivyTypes.NewTestMetadata(),
									CloudwatchLogGroupARN: trivyTypes.String("log-group-arn", trivyTypes.NewTestMetadata()),
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
			results := CheckEnableAccessLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableAccessLogging.LongID() {
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
