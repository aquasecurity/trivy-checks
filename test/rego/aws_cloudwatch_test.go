package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/cloudtrail"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/cloudwatch"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(awsCloudWatchTestCases)
}

var awsCloudWatchTestCases = testCases{
	"AVD-AWS-0017": {
		{
			name: "AWS CloudWatch with unencrypted log group",
			input: state.State{AWS: aws.AWS{CloudWatch: cloudwatch.CloudWatch{
				LogGroups: []cloudwatch.LogGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						KMSKeyID: trivyTypes.String("", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS CloudWatch with encrypted log group",
			input: state.State{AWS: aws.AWS{CloudWatch: cloudwatch.CloudWatch{
				LogGroups: []cloudwatch.LogGroup{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						KMSKeyID: trivyTypes.String("some-kms-key", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0151": {
		{
			name: "Multi-region CloudTrail alarms on CloudTrail configuration change",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  trivyTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Arn:      trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{
								{
									Metadata:      trivyTypes.NewTestMetadata(),
									FilterName:    trivyTypes.String("CloudTrailConfigurationChange", trivyTypes.NewTestMetadata()),
									FilterPattern: trivyTypes.String(`   {($.eventName=CreateTrail) || ($.eventName=UpdateTrail) || ($.eventName=DeleteTrail) || ($.eventName=StartLogging) || ($.eventName=StopLogging)}`, trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:   trivyTypes.NewTestMetadata(),
							AlarmName:  trivyTypes.String("CloudTrailConfigurationChange", trivyTypes.NewTestMetadata()),
							MetricName: trivyTypes.String("CloudTrailConfigurationChange", trivyTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									ID:       trivyTypes.String("CloudTrailConfigurationChange", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "Multi-region CloudTrail has no filter for CloudTrail configuration change",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  trivyTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
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
							AlarmName: trivyTypes.String("CloudTrailConfigurationChange", trivyTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{},
							},
						},
					},
				},
			}},
			expected: true,
		},
	},
	"AVD-AWS-0153": {
		{
			name: "Multi-region CloudTrail alarms on CMK disabled or scheduled deletion",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  trivyTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Arn:      trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{
								{
									Metadata:      trivyTypes.NewTestMetadata(),
									FilterName:    trivyTypes.String("CMKDisbledOrScheduledDelete", trivyTypes.NewTestMetadata()),
									FilterPattern: trivyTypes.String(`{($.eventSource=kms.amazonaws.com) && (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion))}`, trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:   trivyTypes.NewTestMetadata(),
							AlarmName:  trivyTypes.String("CMKDisbledOrScheduledDelete", trivyTypes.NewTestMetadata()),
							MetricName: trivyTypes.String("CMKDisbledOrScheduledDelete", trivyTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									ID:       trivyTypes.String("CMKDisbledOrScheduledDelete", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "Multi-region CloudTrail has no filter for CMK Disabled or scheduled deletion",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  trivyTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
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
							AlarmName: trivyTypes.String("CMKDisbledOrScheduledDelete", trivyTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{},
							},
						},
					},
				},
			}},
			expected: true,
		},
	},
	"AVD-AWS-0155": {
		{
			name: "Multi-region CloudTrail alarms on Config configuration change",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  trivyTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Arn:      trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{
								{
									Metadata:      trivyTypes.NewTestMetadata(),
									FilterName:    trivyTypes.String("ConfigConfigurationChange", trivyTypes.NewTestMetadata()),
									FilterPattern: trivyTypes.String(`{($.eventSource=config.amazonaws.com) && (($.eventName=StopConfigurationRecorder) || ($.eventName=DeleteDeliveryChannel) || ($.eventName=PutDeliveryChannel) || ($.eventName=PutConfigurationRecorder))}`, trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:   trivyTypes.NewTestMetadata(),
							AlarmName:  trivyTypes.String("ConfigConfigurationChange", trivyTypes.NewTestMetadata()),
							MetricName: trivyTypes.String("ConfigConfigurationChange", trivyTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									ID:       trivyTypes.String("ConfigConfigurationChange", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "Multi-region CloudTrail has no filter for Config configuration change",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  trivyTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
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
							AlarmName: trivyTypes.String("ConfigConfigurationChange", trivyTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{},
							},
						},
					},
				},
			}},
			expected: true,
		},
	},
	"AVD-AWS-0152": {
		{
			name: "Multi-region CloudTrail alarms on Console login failure",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  trivyTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Arn:      trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{
								{
									Metadata:      trivyTypes.NewTestMetadata(),
									FilterName:    trivyTypes.String("ConsoleLoginFailure", trivyTypes.NewTestMetadata()),
									FilterPattern: trivyTypes.String(`{($.eventName=ConsoleLogin) && ($.errorMessage="Failed authentication")}`, trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:   trivyTypes.NewTestMetadata(),
							AlarmName:  trivyTypes.String("ConsoleLoginFailure", trivyTypes.NewTestMetadata()),
							MetricName: trivyTypes.String("ConsoleLoginFailure", trivyTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									ID:       trivyTypes.String("ConsoleLoginFailure", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "Multi-region CloudTrail has no filter for console login failure",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  trivyTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
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
							AlarmName: trivyTypes.String("ConsoleLoginFailure", trivyTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{},
							},
						},
					},
				},
			}},
			expected: true,
		},
	},
	"AVD-AWS-0150": {
		{
			name: "Multi-region CloudTrail alarms on IAM Policy change",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  trivyTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Arn:      trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{
								{
									Metadata:   trivyTypes.NewTestMetadata(),
									FilterName: trivyTypes.String("IAMPolicyChanged", trivyTypes.NewTestMetadata()),
									FilterPattern: trivyTypes.String(`{($.eventName=DeleteGroupPolicy) || 
	($.eventName=DeleteRolePolicy) || 
	($.eventName=DeleteUserPolicy) || 
	($.eventName=PutGroupPolicy) || 
	($.eventName=PutRolePolicy) || 
	($.eventName=PutUserPolicy) || 
	($.eventName=CreatePolicy) || 
	($.eventName=DeletePolicy) || 
	($.eventName=CreatePolicyVersion) || 
	($.eventName=DeletePolicyVersion) || 
	($.eventName=AttachRolePolicy) ||
	($.eventName=DetachRolePolicy) ||
	($.eventName=AttachUserPolicy) || 
	($.eventName=DetachUserPolicy) || 
	($.eventName=AttachGroupPolicy) || 
	($.eventName=DetachGroupPolicy)}`, trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:   trivyTypes.NewTestMetadata(),
							AlarmName:  trivyTypes.String("IAMPolicyChanged", trivyTypes.NewTestMetadata()),
							MetricName: trivyTypes.String("IAMPolicyChanged", trivyTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									ID:       trivyTypes.String("IAMPolicyChanged", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "Multi-region CloudTrail has no filter for IAM Policy change",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  trivyTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
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
			}},
			expected: true,
		},
	},
	"AVD-AWS-0157": {
		{
			name: "Multi-region CloudTrail alarms on network acl changes",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  trivyTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Arn:      trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{
								{
									Metadata:   trivyTypes.NewTestMetadata(),
									FilterName: trivyTypes.String("NACLChange", trivyTypes.NewTestMetadata()),
									FilterPattern: trivyTypes.String(`{($.eventName=CreateNetworkAcl) || 
						($.eventName=CreateNetworkAclEntry) || ($.eventName=DeleteNetworkAcl) || 
						($.eventName=DeleteNetworkAclEntry) || ($.eventName=ReplaceNetworkAclEntry) || 
						($.eventName=ReplaceNetworkAclAssociation)}`, trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:   trivyTypes.NewTestMetadata(),
							AlarmName:  trivyTypes.String("NACLChange", trivyTypes.NewTestMetadata()),
							MetricName: trivyTypes.String("NACLChange", trivyTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									ID:       trivyTypes.String("NACLChange", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "Multi-region CloudTrail has no filter for network acl changes",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  trivyTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
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
							AlarmName: trivyTypes.String("NACLChange", trivyTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{},
							},
						},
					},
				},
			}},
			expected: true,
		},
	},
	"AVD-AWS-0158": {
		{
			name: "Multi-region CloudTrail alarms on network gateway changes",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  trivyTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Arn:      trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{
								{
									Metadata:   trivyTypes.NewTestMetadata(),
									FilterName: trivyTypes.String("NetworkGatewayChange", trivyTypes.NewTestMetadata()),
									FilterPattern: trivyTypes.String(`{($.eventName=CreateCustomerGateway) || 
						($.eventName=DeleteCustomerGateway) || ($.eventName=AttachInternetGateway) || 
						($.eventName=CreateInternetGateway) || ($.eventName=DeleteInternetGateway) || 
						($.eventName=DetachInternetGateway)}`, trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:   trivyTypes.NewTestMetadata(),
							AlarmName:  trivyTypes.String("NetworkGatewayChange", trivyTypes.NewTestMetadata()),
							MetricName: trivyTypes.String("NetworkGatewayChange", trivyTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									ID:       trivyTypes.String("NetworkGatewayChange", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "Multi-region CloudTrail has no filter for network gateway changes",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  trivyTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
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
							AlarmName: trivyTypes.String("NetworkGatewayChange", trivyTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{},
							},
						},
					},
				},
			}},
			expected: true,
		},
	},
	"AVD-AWS-0148": {
		{
			name: "Multi-region CloudTrail alarms on Non-MFA login",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  trivyTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
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
			}},
			expected: false,
		},
		{
			name: "Multi-region CloudTrail has no filter for Unauthorized API calls",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  trivyTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
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
			}},
			expected: true,
		},
	},
	"AVD-AWS-0174": {
		{
			name: "alarm exists",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  trivyTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
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
			}},
			expected: false,
		},
		{
			name: "metric filter does not exist",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  trivyTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Arn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}},
			expected: true,
		},
		{
			name: "alarm does not exist",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  trivyTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
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
			}},
			expected: true,
		},
	},
	"AVD-AWS-0149": {
		{
			name: "Multi-region CloudTrail alarms on Non-MFA login",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  trivyTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Arn:      trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{
								{
									Metadata:      trivyTypes.NewTestMetadata(),
									FilterName:    trivyTypes.String("RootUserUsage", trivyTypes.NewTestMetadata()),
									FilterPattern: trivyTypes.String(`$.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && &.eventType != "AwsServiceEvent"`, trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:   trivyTypes.NewTestMetadata(),
							AlarmName:  trivyTypes.String("RootUserUsage", trivyTypes.NewTestMetadata()),
							MetricName: trivyTypes.String("RootUserUsage", trivyTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									ID:       trivyTypes.String("RootUserUsage", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "Multi-region CloudTrail alarms on Non-MFA login",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  trivyTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata:      trivyTypes.NewTestMetadata(),
							Arn:           trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:   trivyTypes.NewTestMetadata(),
							AlarmName:  trivyTypes.String("RootUserUsage", trivyTypes.NewTestMetadata()),
							MetricName: trivyTypes.String("RootUserUsage", trivyTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									ID:       trivyTypes.String("RootUserUsage", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: true,
		},
	},
	"AVD-AWS-0154": {
		{
			name: "Multi-region CloudTrail alarms on S3 bucket policy change",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  trivyTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Arn:      trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{
								{
									Metadata:   trivyTypes.NewTestMetadata(),
									FilterName: trivyTypes.String("BucketPolicyChange", trivyTypes.NewTestMetadata()),
									FilterPattern: trivyTypes.String(`{($.eventSource=s3.amazonaws.com) && (($.eventName=PutBucketAcl) || 
						($.eventName=PutBucketPolicy) || ($.eventName=PutBucketCors) || ($.eventName=PutBucketLifecycle) || 
						($.eventName=PutBucketReplication) || ($.eventName=DeleteBucketPolicy) || ($.eventName=DeleteBucketCors) ||
						 ($.eventName=DeleteBucketLifecycle) || ($.eventName=DeleteBucketReplication))}`, trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:   trivyTypes.NewTestMetadata(),
							AlarmName:  trivyTypes.String("BucketPolicyChange", trivyTypes.NewTestMetadata()),
							MetricName: trivyTypes.String("BucketPolicyChange", trivyTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									ID:       trivyTypes.String("BucketPolicyChange", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "Multi-region CloudTrail has no filter for S3 bucket policy change",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  trivyTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
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
							AlarmName: trivyTypes.String("BucketPolicyChange", trivyTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{},
							},
						},
					},
				},
			}},
			expected: true,
		},
	},
	"AVD-AWS-0156": {
		{
			name: "Multi-region CloudTrail alarms on security group changes",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  trivyTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Arn:      trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{
								{
									Metadata:   trivyTypes.NewTestMetadata(),
									FilterName: trivyTypes.String("SecurityGroupChange", trivyTypes.NewTestMetadata()),
									FilterPattern: trivyTypes.String(`{($.eventName=AuthorizeSecurityGroupIngress) || 
						($.eventName=AuthorizeSecurityGroupEgress) || ($.eventName=RevokeSecurityGroupIngress) ||
						($.eventName=RevokeSecurityGroupEgress) || ($.eventName=CreateSecurityGroup) || 
						($.eventName=DeleteSecurityGroup)}`, trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:   trivyTypes.NewTestMetadata(),
							AlarmName:  trivyTypes.String("SecurityGroupChange", trivyTypes.NewTestMetadata()),
							MetricName: trivyTypes.String("SecurityGroupChange", trivyTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									ID:       trivyTypes.String("SecurityGroupChange", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "Multi-region CloudTrail has no filter for security group changes",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  trivyTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
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
							AlarmName: trivyTypes.String("SecurityGroupChange", trivyTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{},
							},
						},
					},
				},
			}},
			expected: true,
		},
	},
	"AVD-AWS-0147": {
		{
			name: "Multi-region CloudTrail alarms on Unauthorized API calls",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  trivyTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Arn:      trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{
								{
									Metadata:      trivyTypes.NewTestMetadata(),
									FilterName:    trivyTypes.String("UnauthorizedAPIUsage", trivyTypes.NewTestMetadata()),
									FilterPattern: trivyTypes.String(`($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*")`, trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:   trivyTypes.NewTestMetadata(),
							AlarmName:  trivyTypes.String("CloudTrail_Unauthorized_API_Call", trivyTypes.NewTestMetadata()),
							MetricName: trivyTypes.String("UnauthorizedAPIUsage", trivyTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									ID:       trivyTypes.String("UnauthorizedAPIUsage", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "Multi-region CloudTrail has no filter for Unauthorized API calls",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  trivyTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
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
			}},
			expected: true,
		},
	},
	"AVD-AWS-0160": {
		{
			name: "Multi-region CloudTrail alarms on VPC changes",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  trivyTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Arn:      trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{
								{
									Metadata:   trivyTypes.NewTestMetadata(),
									FilterName: trivyTypes.String("VPCChange", trivyTypes.NewTestMetadata()),
									FilterPattern: trivyTypes.String(`{($.eventName=CreateVpc) || 
						($.eventName=DeleteVpc) || ($.eventName=ModifyVpcAttribute) || 
						($.eventName=AcceptVpcPeeringConnection) || ($.eventName=CreateVpcPeeringConnection) || 
						($.eventName=DeleteVpcPeeringConnection) || ($.eventName=RejectVpcPeeringConnection) || 
						($.eventName=AttachClassicLinkVpc) || ($.eventName=DetachClassicLinkVpc) || 
						($.eventName=DisableVpcClassicLink) || ($.eventName=EnableVpcClassicLink)}`, trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:   trivyTypes.NewTestMetadata(),
							AlarmName:  trivyTypes.String("VPCChange", trivyTypes.NewTestMetadata()),
							MetricName: trivyTypes.String("VPCChange", trivyTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									ID:       trivyTypes.String("VPCChange", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "Multi-region CloudTrail has no filter for VPC changes",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  trivyTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", trivyTypes.NewTestMetadata()),
							IsLogging:                 trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							IsMultiRegion:             trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
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
							AlarmName: trivyTypes.String("VPCChange", trivyTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{},
							},
						},
					},
				},
			}},
			expected: true,
		},
	},
}
