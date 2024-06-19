package iam

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/iam"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoUserGrantedPermissions(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "Permissions granted to users",
			input: iam.IAM{
				Projects: []iam.Project{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Member:   trivyTypes.String("user:test@example.com", trivyTypes.NewTestMetadata()),
								Role:     trivyTypes.String("some-role", trivyTypes.NewTestMetadata()),
							},
						},
						Bindings: []iam.Binding{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Members: []trivyTypes.StringValue{
									trivyTypes.String("user:test@example.com", trivyTypes.NewTestMetadata()),
								},
								Role: trivyTypes.String("some-role", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Permissions granted to users #2",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Member:   trivyTypes.String("user:test@example.com", trivyTypes.NewTestMetadata()),
								Role:     trivyTypes.String("some-role", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Permissions granted to users #3",
			input: iam.IAM{
				Folders: []iam.Folder{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Member:   trivyTypes.String("user:test@example.com", trivyTypes.NewTestMetadata()),
								Role:     trivyTypes.String("some-role", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Permissions granted to users #4",
			input: iam.IAM{
				Folders: []iam.Folder{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Bindings: []iam.Binding{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Members: []trivyTypes.StringValue{
									trivyTypes.String("user:test@example.com", trivyTypes.NewTestMetadata()),
								},
								Role: trivyTypes.String("some-role", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Permissions granted on groups",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Member:   trivyTypes.String("group:test@example.com", trivyTypes.NewTestMetadata()),
								Role:     trivyTypes.String("some-role", trivyTypes.NewTestMetadata()),
							},
						},
						Bindings: []iam.Binding{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Members: []trivyTypes.StringValue{
									trivyTypes.String("group:test@example.com", trivyTypes.NewTestMetadata()),
								},
								Role: trivyTypes.String("some-role", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
				Folders: []iam.Folder{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Bindings: []iam.Binding{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Members: []trivyTypes.StringValue{
									trivyTypes.String("group:test@example.com", trivyTypes.NewTestMetadata()),
								},
								Role: trivyTypes.String("some-role", trivyTypes.NewTestMetadata()),
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
			results := CheckNoUserGrantedPermissions.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoUserGrantedPermissions.LongID() {
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
