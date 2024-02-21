package codebuild

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/codebuild"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    codebuild.CodeBuild
		expected bool
	}{
		{
			name: "AWS Codebuild project with unencrypted artifact",
			input: codebuild.CodeBuild{
				Projects: []codebuild.Project{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ArtifactSettings: codebuild.ArtifactSettings{
							Metadata:          trivyTypes.NewTestMetadata(),
							EncryptionEnabled: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS Codebuild project with unencrypted secondary artifact",
			input: codebuild.CodeBuild{
				Projects: []codebuild.Project{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ArtifactSettings: codebuild.ArtifactSettings{
							Metadata:          trivyTypes.NewTestMetadata(),
							EncryptionEnabled: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
						SecondaryArtifactSettings: []codebuild.ArtifactSettings{
							{
								Metadata:          trivyTypes.NewTestMetadata(),
								EncryptionEnabled: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS Codebuild with encrypted artifacts",
			input: codebuild.CodeBuild{
				Projects: []codebuild.Project{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ArtifactSettings: codebuild.ArtifactSettings{
							Metadata:          trivyTypes.NewTestMetadata(),
							EncryptionEnabled: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
						SecondaryArtifactSettings: []codebuild.ArtifactSettings{
							{
								Metadata:          trivyTypes.NewTestMetadata(),
								EncryptionEnabled: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
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
			testState.AWS.CodeBuild = test.input
			results := CheckEnableEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableEncryption.LongID() {
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
