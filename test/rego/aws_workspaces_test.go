package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/workspaces"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(awsWorkspacesTestCases)
}

var awsWorkspacesTestCases = testCases{
	"AVD-AWS-0109": {
		{
			name: "AWS Workspace with unencrypted root volume",
			input: state.State{AWS: aws.AWS{WorkSpaces: workspaces.WorkSpaces{
				WorkSpaces: []workspaces.WorkSpace{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						RootVolume: workspaces.Volume{
							Metadata: trivyTypes.NewTestMetadata(),
							Encryption: workspaces.Encryption{
								Metadata: trivyTypes.NewTestMetadata(),
								Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							},
						},
						UserVolume: workspaces.Volume{
							Metadata: trivyTypes.NewTestMetadata(),
							Encryption: workspaces.Encryption{
								Metadata: trivyTypes.NewTestMetadata(),
								Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS Workspace with unencrypted user volume",
			input: state.State{AWS: aws.AWS{WorkSpaces: workspaces.WorkSpaces{
				WorkSpaces: []workspaces.WorkSpace{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						RootVolume: workspaces.Volume{
							Metadata: trivyTypes.NewTestMetadata(),
							Encryption: workspaces.Encryption{
								Metadata: trivyTypes.NewTestMetadata(),
								Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
						},
						UserVolume: workspaces.Volume{
							Metadata: trivyTypes.NewTestMetadata(),
							Encryption: workspaces.Encryption{
								Metadata: trivyTypes.NewTestMetadata(),
								Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},

		{
			name: "AWS Workspace with encrypted user and root volumes",
			input: state.State{AWS: aws.AWS{WorkSpaces: workspaces.WorkSpaces{
				WorkSpaces: []workspaces.WorkSpace{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						RootVolume: workspaces.Volume{
							Metadata: trivyTypes.NewTestMetadata(),
							Encryption: workspaces.Encryption{
								Metadata: trivyTypes.NewTestMetadata(),
								Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
						},
						UserVolume: workspaces.Volume{
							Metadata: trivyTypes.NewTestMetadata(),
							Encryption: workspaces.Encryption{
								Metadata: trivyTypes.NewTestMetadata(),
								Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
