package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/config"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(awsConfigTestCases)
}

var awsConfigTestCases = testCases{
	"AVD-AWS-0019": {
		{
			name: "AWS Config aggregator source with all regions set to false",
			input: state.State{AWS: aws.AWS{Config: config.Config{
				ConfigurationAggregrator: config.ConfigurationAggregrator{
					Metadata:         trivyTypes.NewTestMetadata(),
					SourceAllRegions: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
				},
			},
			}},
			expected: true,
		},
		{
			name: "AWS Config aggregator source with all regions set to true",
			input: state.State{AWS: aws.AWS{Config: config.Config{
				ConfigurationAggregrator: config.ConfigurationAggregrator{
					Metadata:         trivyTypes.NewTestMetadata(),
					SourceAllRegions: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
				},
			}}},
			expected: false,
		},
	},
}
