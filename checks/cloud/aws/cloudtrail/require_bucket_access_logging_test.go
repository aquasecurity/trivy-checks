package cloudtrail

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/cloudtrail"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/s3"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckBucketAccessLoggingRequired(t *testing.T) {
	tests := []struct {
		name     string
		inputCT  cloudtrail.CloudTrail
		inputS3  s3.S3
		expected bool
	}{
		{
			name: "Trail has bucket with logging enabled",
			inputCT: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						BucketName: trivyTypes.String("my-bucket", trivyTypes.NewTestMetadata()),
					},
				},
			},
			inputS3: s3.S3{
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
			expected: false,
		},
		{
			name: "Trail has bucket without logging enabled",
			inputCT: cloudtrail.CloudTrail{
				Trails: []cloudtrail.Trail{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						BucketName: trivyTypes.String("my-bucket", trivyTypes.NewTestMetadata()),
					},
				},
			},
			inputS3: s3.S3{
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
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.CloudTrail = test.inputCT
			testState.AWS.S3 = test.inputS3
			results := checkBucketAccessLoggingRequired.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == checkBucketAccessLoggingRequired.LongID() {
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
