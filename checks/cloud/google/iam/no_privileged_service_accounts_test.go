package iam

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/iam"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPrivilegedServiceAccounts(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "Service account granted owner role",
			input: iam.IAM{
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
			},
			expected: true,
		},
		{
			name: "Service account granted editor role",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Folders: []iam.Folder{
							{
								Metadata: trivyTypes.NewTestMetadata(),
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
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "No service account with excessive privileges",
			input: iam.IAM{
				Organizations: []iam.Organization{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Folders: []iam.Folder{
							{
								Metadata: trivyTypes.NewTestMetadata(),
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
			results := CheckNoPrivilegedServiceAccounts.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPrivilegedServiceAccounts.LongID() {
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
