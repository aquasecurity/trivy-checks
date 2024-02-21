package ecs

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/ecs"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPlaintextSecrets(t *testing.T) {
	tests := []struct {
		name     string
		input    ecs.ECS
		expected bool
	}{
		{
			name: "Task definition with plaintext sensitive information",
			input: ecs.ECS{
				TaskDefinitions: []ecs.TaskDefinition{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ContainerDefinitions: []ecs.ContainerDefinition{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								Name:      trivyTypes.String("my_service", trivyTypes.NewTestMetadata()),
								Image:     trivyTypes.String("my_image", trivyTypes.NewTestMetadata()),
								CPU:       trivyTypes.Int(2, trivyTypes.NewTestMetadata()),
								Memory:    trivyTypes.Int(256, trivyTypes.NewTestMetadata()),
								Essential: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								Environment: []ecs.EnvVar{
									{
										Name:  "ENVIRONMENT",
										Value: "development",
									},
									{
										Name:  "DATABASE_PASSWORD",
										Value: "password123",
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
			name: "Task definition without sensitive information",
			input: ecs.ECS{
				TaskDefinitions: []ecs.TaskDefinition{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ContainerDefinitions: []ecs.ContainerDefinition{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								Name:      trivyTypes.String("my_service", trivyTypes.NewTestMetadata()),
								Image:     trivyTypes.String("my_image", trivyTypes.NewTestMetadata()),
								CPU:       trivyTypes.Int(2, trivyTypes.NewTestMetadata()),
								Memory:    trivyTypes.Int(256, trivyTypes.NewTestMetadata()),
								Essential: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								Environment: []ecs.EnvVar{
									{
										Name:  "ENVIRONMENT",
										Value: "development",
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
			testState.AWS.ECS = test.input
			results := CheckNoPlaintextSecrets.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPlaintextSecrets.LongID() {
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
