package lambda

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/lambda"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckRestrictSourceArn(t *testing.T) {
	tests := []struct {
		name     string
		input    lambda.Lambda
		expected bool
	}{
		{
			name: "Lambda function permission missing source ARN",
			input: lambda.Lambda{
				Functions: []lambda.Function{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Permissions: []lambda.Permission{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								Principal: trivyTypes.String("sns.amazonaws.com", trivyTypes.NewTestMetadata()),
								SourceARN: trivyTypes.String("", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Lambda function permission with source ARN",
			input: lambda.Lambda{
				Functions: []lambda.Function{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Permissions: []lambda.Permission{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								Principal: trivyTypes.String("sns.amazonaws.com", trivyTypes.NewTestMetadata()),
								SourceARN: trivyTypes.String("source-arn", trivyTypes.NewTestMetadata()),
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
			testState.AWS.Lambda = test.input
			results := CheckRestrictSourceArn.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckRestrictSourceArn.LongID() {
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
