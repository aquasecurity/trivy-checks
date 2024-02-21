package accessanalyzer

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/accessanalyzer"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestASCheckNoSecretsInUserData(t *testing.T) {
	tests := []struct {
		name     string
		input    accessanalyzer.AccessAnalyzer
		expected bool
	}{
		{
			name:     "No analyzers enabled",
			input:    accessanalyzer.AccessAnalyzer{},
			expected: true,
		},
		{
			name: "Analyzer disabled",
			input: accessanalyzer.AccessAnalyzer{
				Analyzers: []accessanalyzer.Analyzer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ARN:      trivyTypes.String("arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test", trivyTypes.NewTestMetadata()),
						Name:     trivyTypes.String("test", trivyTypes.NewTestMetadata()),
						Active:   trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Analyzer enabled",
			input: accessanalyzer.AccessAnalyzer{
				Analyzers: []accessanalyzer.Analyzer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ARN:      trivyTypes.String("arn:aws:accessanalyzer:us-east-1:123456789012:analyzer/test", trivyTypes.NewTestMetadata()),
						Name:     trivyTypes.String("test", trivyTypes.NewTestMetadata()),
						Active:   trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.AccessAnalyzer = test.input
			results := CheckEnableAccessAnalyzer.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableAccessAnalyzer.LongID() {
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
