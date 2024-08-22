package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/cloudtrail"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/s3"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(awsCloudTrailTestCases)
}

var awsCloudTrailTestCases = testCases{
	"AVD-AWS-0014": {
		{
			name: "AWS CloudTrail not enabled across all regions",
			input: state.State{AWS: aws.AWS{CloudTrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:      trivyTypes.NewTestMetadata(),
						IsMultiRegion: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS CloudTrail enabled across all regions",
			input: state.State{AWS: aws.AWS{CloudTrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:      trivyTypes.NewTestMetadata(),
						IsMultiRegion: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0016": {
		{
			name: "AWS CloudTrail without logfile validation",
			input: state.State{AWS: aws.AWS{CloudTrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:                trivyTypes.NewTestMetadata(),
						EnableLogFileValidation: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS CloudTrail with logfile validation enabled",
			input: state.State{AWS: aws.AWS{CloudTrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:                trivyTypes.NewTestMetadata(),
						EnableLogFileValidation: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0015": {
		{
			name: "AWS CloudTrail without CMK",
			input: state.State{AWS: aws.AWS{CloudTrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						KMSKeyID: trivyTypes.String("", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS CloudTrail with CMK",
			input: state.State{AWS: aws.AWS{CloudTrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						KMSKeyID: trivyTypes.String("some-kms-key", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0162": {
		{
			name: "Trail has cloudwatch configured",
			input: state.State{AWS: aws.AWS{CloudTrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:                  trivyTypes.NewTestMetadata(),
						CloudWatchLogsLogGroupArn: trivyTypes.String("arn:aws:logs:us-east-1:123456789012:log-group:my-log-group", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Trail does not have cloudwatch configured",
			input: state.State{AWS: aws.AWS{CloudTrail: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:                  trivyTypes.NewTestMetadata(),
						CloudWatchLogsLogGroupArn: trivyTypes.String("", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
	},
	"AVD-AWS-0161": {
		{
			name: "Trail has bucket with no public access",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:   trivyTypes.NewTestMetadata(),
							BucketName: trivyTypes.String("my-bucket", trivyTypes.NewTestMetadata()),
						},
					},
				},
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Name:     trivyTypes.String("my-bucket", trivyTypes.NewTestMetadata()),
							ACL:      trivyTypes.String("private", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "Trail has bucket with public access",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:   trivyTypes.NewTestMetadata(),
							BucketName: trivyTypes.String("my-bucket", trivyTypes.NewTestMetadata()),
						},
					},
				},
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Name:     trivyTypes.String("my-bucket", trivyTypes.NewTestMetadata()),
							ACL:      trivyTypes.String("public-read", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}},
			expected: true,
		},
	},
	"AVD-AWS-0163": {
		{
			name: "Trail has bucket with logging enabled",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:   trivyTypes.NewTestMetadata(),
							BucketName: trivyTypes.String("my-bucket", trivyTypes.NewTestMetadata()),
						},
					},
				},
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Name:     trivyTypes.String("my-bucket", trivyTypes.NewTestMetadata()),
							Logging: s3.Logging{
								Metadata: trivyTypes.NewTestMetadata(),
								Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "Trail has bucket without logging enabled",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:   trivyTypes.NewTestMetadata(),
							BucketName: trivyTypes.String("my-bucket", trivyTypes.NewTestMetadata()),
						},
					},
				},
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Name:     trivyTypes.String("my-bucket", trivyTypes.NewTestMetadata()),
							Logging: s3.Logging{
								Metadata: trivyTypes.NewTestMetadata(),
								Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}},
			expected: true,
		},
	},
}
