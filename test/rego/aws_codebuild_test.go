package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/codebuild"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

var awsCodeBuildTestCases = testCases{
	"AVD-AWS-0018": {
		{
			name: "AWS Codebuild project with unencrypted artifact",
			input: state.State{AWS: aws.AWS{CodeBuild: codebuild.CodeBuild{
				Projects: []codebuild.Project{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ArtifactSettings: codebuild.ArtifactSettings{
							Metadata:          trivyTypes.NewTestMetadata(),
							EncryptionEnabled: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS Codebuild project with unencrypted secondary artifact",
			input: state.State{AWS: aws.AWS{CodeBuild: codebuild.CodeBuild{
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
			}}},
			expected: true,
		},
		{
			name: "AWS Codebuild with encrypted artifacts",
			input: state.State{AWS: aws.AWS{CodeBuild: codebuild.CodeBuild{
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
			}}},
			expected: false,
		},
	},
}
