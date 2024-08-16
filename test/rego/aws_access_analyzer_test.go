package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/accessanalyzer"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

var awsAccessAnalyzerTestCases = testCases{
	"AVD-AWS-0175": {
		// TODO: Trivy does not export empty structures into Rego
		// {

		// 	name:     "No analyzers enabled",
		// 	input:    state.State{AWS: aws.AWS{AccessAnalyzer: accessanalyzer.AccessAnalyzer{}}},
		// 	expected: true,
		// },
		{
			name: "Analyzer disabled",
			input: state.State{AWS: aws.AWS{AccessAnalyzer: accessanalyzer.AccessAnalyzer{
				Analyzers: []accessanalyzer.Analyzer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ARN:      trivyTypes.String("arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test", trivyTypes.NewTestMetadata()),
						Name:     trivyTypes.String("test", trivyTypes.NewTestMetadata()),
						Active:   trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Analyzer enabled",
			input: state.State{AWS: aws.AWS{AccessAnalyzer: accessanalyzer.AccessAnalyzer{
				Analyzers: []accessanalyzer.Analyzer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ARN:      trivyTypes.String("arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test", trivyTypes.NewTestMetadata()),
						Name:     trivyTypes.String("test", trivyTypes.NewTestMetadata()),
						Active:   trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				}}},
			},
			expected: false,
		},
	},
}
