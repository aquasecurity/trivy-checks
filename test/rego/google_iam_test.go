package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/google"
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/iam"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

var googleIamTestCases = testCases{
	"AVD-GCP-0068": {
		{
			name: "Workload identity pool without condition",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				WorkloadIdentityPoolProviders: []iam.WorkloadIdentityPoolProvider{
					{
						Metadata:                       trivyTypes.NewTestMetadata(),
						WorkloadIdentityPoolId:         trivyTypes.String("example-pool", trivyTypes.NewTestMetadata()),
						WorkloadIdentityPoolProviderId: trivyTypes.String("example-provider", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Workload identity pool with empty condition",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				WorkloadIdentityPoolProviders: []iam.WorkloadIdentityPoolProvider{
					{
						Metadata:                       trivyTypes.NewTestMetadata(),
						WorkloadIdentityPoolId:         trivyTypes.String("example-pool", trivyTypes.NewTestMetadata()),
						WorkloadIdentityPoolProviderId: trivyTypes.String("example-provider", trivyTypes.NewTestMetadata()),
						AttributeCondition:             trivyTypes.String("", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Workload identity pool with non-empty condition",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				WorkloadIdentityPoolProviders: []iam.WorkloadIdentityPoolProvider{
					{
						Metadata:                       trivyTypes.NewTestMetadata(),
						WorkloadIdentityPoolId:         trivyTypes.String("example-pool", trivyTypes.NewTestMetadata()),
						WorkloadIdentityPoolProviderId: trivyTypes.String("example-provider", trivyTypes.NewTestMetadata()),
						AttributeCondition:             trivyTypes.String("assertion.repository_owner=='your-github-organization'", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0010": {
		{
			name: "Project automatic network creation enabled",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Projects: []iam.Project{
					{
						Metadata:          trivyTypes.NewTestMetadata(),
						AutoCreateNetwork: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Project automatic network creation enabled #2",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Projects: []iam.Project{
					{
						Metadata:          trivyTypes.NewTestMetadata(),
						AutoCreateNetwork: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
					{
						Metadata:          trivyTypes.NewTestMetadata(),
						AutoCreateNetwork: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Project automatic network creation disabled",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Projects: []iam.Project{
					{
						Metadata:          trivyTypes.NewTestMetadata(),
						AutoCreateNetwork: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0004": {
		{
			name: "Default service account enabled",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Folders: []iam.Folder{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata:              trivyTypes.NewTestMetadata(),
								DefaultServiceAccount: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								Member:                trivyTypes.String("proper@email.com", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Default service account disabled but default account data provided",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Folders: []iam.Folder{
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
			}}},
			expected: true,
		},
		{
			name: "Default service account disabled but default account data provided #2",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Folders: []iam.Folder{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Bindings: []iam.Binding{
							{
								Metadata:                      trivyTypes.NewTestMetadata(),
								IncludesDefaultServiceAccount: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								Members: []trivyTypes.StringValue{
									trivyTypes.String("123-compute@developer.gserviceaccount.com", trivyTypes.NewTestMetadata())},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Default service account disabled and proper account data provided",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Folders: []iam.Folder{
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
									trivyTypes.String("proper@account.com", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0005": {
		{
			name: "Member role set to service account user",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Folders: []iam.Folder{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Role:     trivyTypes.String("roles/iam.serviceAccountUser", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Binding role set to service account token creator",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Folders: []iam.Folder{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Bindings: []iam.Binding{
							{
								Metadata:                      trivyTypes.NewTestMetadata(),
								IncludesDefaultServiceAccount: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								Role:                          trivyTypes.String("roles/iam.serviceAccountTokenCreator", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Member role set to something particular",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Folders: []iam.Folder{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Role:     trivyTypes.String("roles/nothingInParticular", trivyTypes.NewTestMetadata()),
							},
						},
						Bindings: []iam.Binding{
							{
								Metadata:                      trivyTypes.NewTestMetadata(),
								IncludesDefaultServiceAccount: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								Role:                          trivyTypes.String("roles/nothingInParticular", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0008": {
		{
			name: "Default service account disabled but default account provided",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Bindings: []iam.Binding{
							{
								Metadata:                      trivyTypes.NewTestMetadata(),
								IncludesDefaultServiceAccount: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								Members: []trivyTypes.StringValue{
									trivyTypes.String("123-compute@developer.gserviceaccount.com", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Default service account enabled",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata:              trivyTypes.NewTestMetadata(),
								Member:                trivyTypes.String("proper@email.com", trivyTypes.NewTestMetadata()),
								DefaultServiceAccount: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Default service account disabled and proper account provided",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata:              trivyTypes.NewTestMetadata(),
								Member:                trivyTypes.String("proper@email.com", trivyTypes.NewTestMetadata()),
								DefaultServiceAccount: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
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
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0009": {
		{
			name: "Member role set to service account user",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Role:     trivyTypes.String("roles/iam.serviceAccountUser", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Member role set to service account token creator",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Bindings: []iam.Binding{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Role:     trivyTypes.String("roles/iam.serviceAccountTokenCreator", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},

		{
			name: "Member roles custom set",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Role:     trivyTypes.String("roles/some-custom-role", trivyTypes.NewTestMetadata()),
							},
						},
						Bindings: []iam.Binding{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Role:     trivyTypes.String("roles/some-custom-role", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0007": {
		{
			name: "Service account granted owner role",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Role:     trivyTypes.String("roles/owner", trivyTypes.NewTestMetadata()),
								Member:   trivyTypes.String("serviceAccount:${google_service_account.test.email}", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Service account granted editor role",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Projects: []iam.Project{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Bindings: []iam.Binding{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Role:     trivyTypes.String("roles/editor", trivyTypes.NewTestMetadata()),
								Members: []trivyTypes.StringValue{
									trivyTypes.String("serviceAccount:${google_service_account.test.email}", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "No service account with excessive privileges",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Projects: []iam.Project{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Role:     trivyTypes.String("roles/owner", trivyTypes.NewTestMetadata()),
								Member:   trivyTypes.String("proper@email.com", trivyTypes.NewTestMetadata()),
							},
						},
						Bindings: []iam.Binding{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Role:     trivyTypes.String("roles/logging.logWriter", trivyTypes.NewTestMetadata()),
								Members: []trivyTypes.StringValue{
									trivyTypes.String("serviceAccount:${google_service_account.test.email}", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0006": {
		{
			name: "Default service account disabled but default account used",
			input: state.State{Google: google.Google{IAM: iam.IAM{
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
			}}},
			expected: true,
		},
		{
			name: "Default account enabled",
			input: state.State{Google: google.Google{IAM: iam.IAM{
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
			}}},
			expected: true,
		},
		{
			name: "Default accounts disabled and proper accounts provided",
			input: state.State{Google: google.Google{IAM: iam.IAM{
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
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0011": {
		{
			name: "Project member role set to service account user",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Projects: []iam.Project{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Role:     trivyTypes.String("roles/iam.serviceAccountUser", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Project member role set to service account token creator",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Projects: []iam.Project{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Bindings: []iam.Binding{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Role:     trivyTypes.String("roles/iam.serviceAccountTokenCreator", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Project members set to custom roles",
			input: state.State{Google: google.Google{IAM: iam.IAM{
				Projects: []iam.Project{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Role:     trivyTypes.String("roles/specific-role", trivyTypes.NewTestMetadata()),
							},
						},
						Bindings: []iam.Binding{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Role:     trivyTypes.String("roles/specific-role", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0003": {
		{
			name: "Permissions granted to users",
			input: state.State{Google: google.Google{IAM: iam.IAM{
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
			}}},
			expected: true,
		},
		{
			name: "Permissions granted to users #2",
			input: state.State{Google: google.Google{IAM: iam.IAM{
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
			}}},
			expected: true,
		},
		{
			name: "Permissions granted to users #3",
			input: state.State{Google: google.Google{IAM: iam.IAM{
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
			}}},
			expected: true,
		},
		{
			name: "Permissions granted to users #4",
			input: state.State{Google: google.Google{IAM: iam.IAM{
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
			}}},
			expected: true,
		},
		{
			name: "Permissions granted on groups",
			input: state.State{Google: google.Google{IAM: iam.IAM{
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
			}}},
			expected: false,
		},
	},
}
