package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/authorization"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(azureAuthorizationTestCases)
}

var azureAuthorizationTestCases = testCases{
	"AVD-AZU-0030": {
		{
			name: "Wildcard action with all scopes",
			input: state.State{Azure: azure.Azure{Authorization: authorization.Authorization{
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
			}}},
			expected: true,
		},
		{
			name: "Wildcard action with specific scope",
			input: state.State{Azure: azure.Azure{Authorization: authorization.Authorization{
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
			}}},
			expected: false,
		},
	},
}
