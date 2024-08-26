package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/efs"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(awsEfsTestCases)
}

var awsEfsTestCases = testCases{
	"AVD-AWS-0037": {
		{
			name: "positive result",
			input: state.State{AWS: aws.AWS{EFS: efs.EFS{
				FileSystems: []efs.FileSystem{
					{
						Metadata:  trivyTypes.NewTestMetadata(),
						Encrypted: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					}},
			}}},
			expected: true,
		},
		{
			name: "negative result",
			input: state.State{AWS: aws.AWS{EFS: efs.EFS{
				FileSystems: []efs.FileSystem{
					{
						Metadata:  trivyTypes.NewTestMetadata(),
						Encrypted: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					}},
			}}},
			expected: false,
		},
	},
}
