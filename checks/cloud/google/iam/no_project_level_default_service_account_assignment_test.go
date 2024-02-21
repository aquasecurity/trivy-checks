package iam

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/iam"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoProjectLevelDefaultServiceAccountAssignment(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "Default service account disabled but default account used",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Projects: []iam.Project{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Members: []iam.Member{
									{
										Metadata:              trivyTypes.NewTestMetadata(),
										DefaultServiceAccount: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
										Member:                trivyTypes.String("123-compute@developer.gserviceaccount.com", trivyTypes.NewTestMetadata()),
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
			name: "Default account enabled",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Projects: []iam.Project{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Bindings: []iam.Binding{
									{
										Metadata:                      trivyTypes.NewTestMetadata(),
										IncludesDefaultServiceAccount: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
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
			name: "Default accounts disabled and proper accounts provided",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Projects: []iam.Project{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Members: []iam.Member{
									{
										Metadata:              trivyTypes.NewTestMetadata(),
										DefaultServiceAccount: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
										Member:                trivyTypes.String("proper@email.com", trivyTypes.NewTestMetadata()),
									},
								},
								Bindings: []iam.Binding{
									{
										Metadata:                      trivyTypes.NewTestMetadata(),
										IncludesDefaultServiceAccount: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
										Members: []trivyTypes.StringValue{
											trivyTypes.String("proper@email.com", trivyTypes.NewTestMetadata()),
										},
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
			testState.Google.IAM = test.input
			results := CheckNoProjectLevelDefaultServiceAccountAssignment.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoProjectLevelDefaultServiceAccountAssignment.LongID() {
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
