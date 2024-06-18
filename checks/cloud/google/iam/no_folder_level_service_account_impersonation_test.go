package iam

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/iam"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoFolderLevelServiceAccountImpersonation(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "Member role set to service account user",
			input: iam.IAM{
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
			},
			expected: true,
		},
		{
			name: "Binding role set to service account token creator",
			input: iam.IAM{
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
			},
			expected: true,
		},
		{
			name: "Member role set to something particular",
			input: iam.IAM{
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
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Google.IAM = test.input
			results := CheckNoFolderLevelServiceAccountImpersonation.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoFolderLevelServiceAccountImpersonation.LongID() {
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
