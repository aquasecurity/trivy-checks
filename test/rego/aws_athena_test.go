package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/athena"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(awsAthenaTestCases)
}

var awsAthenaTestCases = testCases{
	"AVD-AWS-0006": {
		{
			name: "AWS Athena database unencrypted",
			input: state.State{AWS: aws.AWS{Athena: athena.Athena{
				Databases: []athena.Database{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: athena.EncryptionConfiguration{
							Metadata: trivyTypes.NewTestMetadata(),
							Type:     trivyTypes.String(athena.EncryptionTypeNone, trivyTypes.NewTestMetadata()),
						},
					},
				}}},
			},
			expected: true,
		},
		{
			name: "AWS Athena workgroup unencrypted",
			input: state.State{AWS: aws.AWS{Athena: athena.Athena{
				Workgroups: []athena.Workgroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: athena.EncryptionConfiguration{
							Metadata: trivyTypes.NewTestMetadata(),
							Type:     trivyTypes.String(athena.EncryptionTypeNone, trivyTypes.NewTestMetadata()),
						},
					},
				}}},
			},
			expected: true,
		},
		{
			name: "AWS Athena database and workgroup encrypted",
			input: state.State{AWS: aws.AWS{Athena: athena.Athena{
				Databases: []athena.Database{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: athena.EncryptionConfiguration{
							Metadata: trivyTypes.NewTestMetadata(),
							Type:     trivyTypes.String(athena.EncryptionTypeSSEKMS, trivyTypes.NewTestMetadata()),
						},
					},
				},
				Workgroups: []athena.Workgroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: athena.EncryptionConfiguration{
							Metadata: trivyTypes.NewTestMetadata(),
							Type:     trivyTypes.String(athena.EncryptionTypeSSEKMS, trivyTypes.NewTestMetadata()),
						},
					},
				}}},
			},
			expected: false,
		},
	},
	"AVD-AWS-0007": {
		{
			name: "AWS Athena workgroup doesn't enforce configuration",
			input: state.State{AWS: aws.AWS{Athena: athena.Athena{
				Workgroups: []athena.Workgroup{
					{
						Metadata:             trivyTypes.NewTestMetadata(),
						EnforceConfiguration: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS Athena workgroup enforces configuration",
			input: state.State{AWS: aws.AWS{Athena: athena.Athena{
				Workgroups: []athena.Workgroup{
					{
						Metadata:             trivyTypes.NewTestMetadata(),
						EnforceConfiguration: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
