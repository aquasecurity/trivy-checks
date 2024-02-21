package msk

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/msk"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableLogging(t *testing.T) {
	tests := []struct {
		name     string
		input    msk.MSK
		expected bool
	}{
		{
			name: "Cluster with logging disabled",
			input: msk.MSK{
				Clusters: []msk.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Logging: msk.Logging{
							Metadata: trivyTypes.NewTestMetadata(),
							Broker: msk.BrokerLogging{
								Metadata: trivyTypes.NewTestMetadata(),
								S3: msk.S3Logging{
									Metadata: trivyTypes.NewTestMetadata(),
									Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								},
								Cloudwatch: msk.CloudwatchLogging{
									Metadata: trivyTypes.NewTestMetadata(),
									Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								},
								Firehose: msk.FirehoseLogging{
									Metadata: trivyTypes.NewTestMetadata(),
									Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Cluster logging to S3",
			input: msk.MSK{
				Clusters: []msk.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Logging: msk.Logging{
							Metadata: trivyTypes.NewTestMetadata(),
							Broker: msk.BrokerLogging{
								Metadata: trivyTypes.NewTestMetadata(),
								S3: msk.S3Logging{
									Metadata: trivyTypes.NewTestMetadata(),
									Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								},
								Cloudwatch: msk.CloudwatchLogging{
									Metadata: trivyTypes.NewTestMetadata(),
									Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								},
								Firehose: msk.FirehoseLogging{
									Metadata: trivyTypes.NewTestMetadata(),
									Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								},
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
			testState.AWS.MSK = test.input
			results := CheckEnableLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableLogging.LongID() {
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
