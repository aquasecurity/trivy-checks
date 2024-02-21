package cloudwatch

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/cloudtrail"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/cloudwatch"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckRequireNonMFALoginAlarm(t *testing.T) {
	tests := []struct {
		name       string
		cloudtrail cloudtrail.CloudTrail
		cloudwatch cloudwatch.CloudWatch
		expected   bool
	}{
		{
			name: "Multi-region CloudTrail alarms on Non-MFA login",
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
						Metadata: trivyTypes.NewTestMetadata(),
						Arn:      trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
						MetricFilters: []cloudwatch.MetricFilter{
							{
								Metadata:   trivyTypes.NewTestMetadata(),
								FilterName: trivyTypes.String("NonMFALogin", trivyTypes.NewTestMetadata()),
								FilterPattern: trivyTypes.String(`($.eventName = "ConsoleLogin") && 
($.additionalEventData.MFAUsed != "Yes") && 
($.userIdentity.type=="IAMUser") && 
($.responseElements.ConsoleLogin == "Success")`, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
				Alarms: []cloudwatch.Alarm{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						AlarmName:  trivyTypes.String("NonMFALogin", trivyTypes.NewTestMetadata()),
						MetricName: trivyTypes.String("NonMFALogin", trivyTypes.NewTestMetadata()),
						Metrics: []cloudwatch.MetricDataQuery{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								ID:       trivyTypes.String("NonMFALogin", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Multi-region CloudTrail has no filter for Unauthorized API calls",
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
						Metadata:      trivyTypes.NewTestMetadata(),
						Arn:           trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
						MetricFilters: []cloudwatch.MetricFilter{},
					},
				},
				Alarms: []cloudwatch.Alarm{
					{
						Metadata:  trivyTypes.NewTestMetadata(),
						AlarmName: trivyTypes.String("CloudTrail_Unauthorized_API_Call", trivyTypes.NewTestMetadata()),
						Metrics: []cloudwatch.MetricDataQuery{
							{},
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
			testState.AWS.CloudWatch = test.cloudwatch
			testState.AWS.CloudTrail = test.cloudtrail
			results := requireNonMFALoginAlarm.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == requireNonMFALoginAlarm.LongID() {
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
