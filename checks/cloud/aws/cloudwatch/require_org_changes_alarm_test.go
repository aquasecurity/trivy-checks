package cloudwatch

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/cloudtrail"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/cloudwatch"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckRequireOrgChangesAlarm(t *testing.T) {
	tests := []struct {
		name       string
		cloudtrail cloudtrail.CloudTrail
		cloudwatch cloudwatch.CloudWatch
		expected   bool
	}{
		{
			name: "alarm exists",
			cloudtrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:                  trivyTypes.NewTestMetadata(),
						CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
						IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			},
			cloudwatch: cloudwatch.CloudWatch{
				LogGroups: []cloudwatch.LogGroup{
					{
						Arn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
						MetricFilters: []cloudwatch.MetricFilter{
							{
								FilterName:    trivyTypes.String("OrganizationEvents", trivyTypes.NewTestMetadata()),
								FilterPattern: trivyTypes.String("{ $.eventSource = \"organizations.amazonaws.com\" }", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
				Alarms: []cloudwatch.Alarm{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						MetricName: trivyTypes.String("OrganizationEvents", trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "metric filter does not exist",
			cloudtrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:                  trivyTypes.NewTestMetadata(),
						CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
						IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			},
			cloudwatch: cloudwatch.CloudWatch{
				LogGroups: []cloudwatch.LogGroup{
					{
						Arn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "alarm does not exist",
			cloudtrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:                  trivyTypes.NewTestMetadata(),
						CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
						IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			},
			cloudwatch: cloudwatch.CloudWatch{
				LogGroups: []cloudwatch.LogGroup{
					{
						Arn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
						MetricFilters: []cloudwatch.MetricFilter{
							{
								FilterName:    trivyTypes.String("OrganizationEvents", trivyTypes.NewTestMetadata()),
								FilterPattern: trivyTypes.String("{ $.eventSource = \"organizations.amazonaws.com\" }", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.CloudTrail = test.cloudtrail
			testState.AWS.CloudWatch = test.cloudwatch
			results := CheckRequireOrgChangesAlarm.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckRequireOrgChangesAlarm.LongID() {
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
