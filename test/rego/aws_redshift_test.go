package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/redshift"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(awsRedshiftTestCases)
}

var awsRedshiftTestCases = testCases{
	"AVD-AWS-0083": {
		{
			name: "Redshift security group without description",
			input: state.State{AWS: aws.AWS{Redshift: redshift.Redshift{
				SecurityGroups: []redshift.SecurityGroup{
					{
						Metadata:    trivyTypes.NewTestMetadata(),
						Description: trivyTypes.String("", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Redshift security group with description",
			input: state.State{AWS: aws.AWS{Redshift: redshift.Redshift{
				SecurityGroups: []redshift.SecurityGroup{
					{
						Metadata:    trivyTypes.NewTestMetadata(),
						Description: trivyTypes.String("security group description", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0084": {
		{
			name: "Redshift Cluster with encryption disabled",
			input: state.State{AWS: aws.AWS{Redshift: redshift.Redshift{
				Clusters: []redshift.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: redshift.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							KMSKeyID: trivyTypes.String("some-key", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Redshift Cluster missing KMS key",
			input: state.State{AWS: aws.AWS{Redshift: redshift.Redshift{
				Clusters: []redshift.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: redshift.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							KMSKeyID: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Redshift Cluster encrypted with KMS key",
			input: state.State{AWS: aws.AWS{Redshift: redshift.Redshift{
				Clusters: []redshift.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: redshift.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							KMSKeyID: trivyTypes.String("some-key", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0085": {
		{
			name: "security groups present",
			input: state.State{AWS: aws.AWS{Redshift: redshift.Redshift{
				SecurityGroups: []redshift.SecurityGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
					},
				},
			}}},
			expected: true,
		},
		{
			name:     "no security groups",
			input:    state.State{AWS: aws.AWS{Redshift: redshift.Redshift{}}},
			expected: false,
		},
	},
	"AVD-AWS-0127": {
		{
			name: "Redshift Cluster missing subnet name",
			input: state.State{AWS: aws.AWS{Redshift: redshift.Redshift{
				Clusters: []redshift.Cluster{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						SubnetGroupName: trivyTypes.String("", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Redshift Cluster with subnet name",
			input: state.State{AWS: aws.AWS{Redshift: redshift.Redshift{
				Clusters: []redshift.Cluster{
					{
						Metadata:        trivyTypes.NewTestMetadata(),
						SubnetGroupName: trivyTypes.String("redshift-subnet", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
