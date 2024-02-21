package authorization

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/authorization"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckLimitRoleActions(t *testing.T) {
	tests := []struct {
		name     string
		input    authorization.Authorization
		expected bool
	}{
		{
			name: "Wildcard action with all scopes",
			input: authorization.Authorization{
				RoleDefinitions: []authorization.RoleDefinition{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Permissions: []authorization.Permission{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Actions: []trivyTypes.StringValue{
									trivyTypes.String("*", trivyTypes.NewTestMetadata()),
								},
							},
						},
						AssignableScopes: []trivyTypes.StringValue{
							trivyTypes.String("/", trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Wildcard action with specific scope",
			input: authorization.Authorization{
				RoleDefinitions: []authorization.RoleDefinition{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Permissions: []authorization.Permission{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Actions: []trivyTypes.StringValue{
									trivyTypes.String("*", trivyTypes.NewTestMetadata()),
								},
							},
						},
						AssignableScopes: []trivyTypes.StringValue{
							trivyTypes.String("proper-scope", trivyTypes.NewTestMetadata()),
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
			testState.Azure.Authorization = test.input
			results := CheckLimitRoleActions.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckLimitRoleActions.LongID() {
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
