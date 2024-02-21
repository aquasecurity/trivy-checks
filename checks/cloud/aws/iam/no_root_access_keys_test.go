package iam

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoRootAccessKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "root user without access key",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Name:       trivyTypes.String("root", trivyTypes.NewTestMetadata()),
						AccessKeys: nil,
					},
				},
			},
			expected: false,
		},
		{
			name: "other user without access key",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Name:       trivyTypes.String("other", trivyTypes.NewTestMetadata()),
						AccessKeys: nil,
					},
				},
			},
			expected: false,
		},
		{
			name: "other user with access key",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Name:     trivyTypes.String("other", trivyTypes.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     trivyTypes.NewTestMetadata(),
								AccessKeyId:  trivyTypes.String("BLAH", trivyTypes.NewTestMetadata()),
								Active:       trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								CreationDate: trivyTypes.TimeUnresolvable(trivyTypes.NewTestMetadata()),
								LastAccess:   trivyTypes.TimeUnresolvable(trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "root user with inactive access key",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Name:     trivyTypes.String("root", trivyTypes.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     trivyTypes.NewTestMetadata(),
								AccessKeyId:  trivyTypes.String("BLAH", trivyTypes.NewTestMetadata()),
								Active:       trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								CreationDate: trivyTypes.TimeUnresolvable(trivyTypes.NewTestMetadata()),
								LastAccess:   trivyTypes.TimeUnresolvable(trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "root user with active access key",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Name:     trivyTypes.String("root", trivyTypes.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     trivyTypes.NewTestMetadata(),
								AccessKeyId:  trivyTypes.String("BLAH", trivyTypes.NewTestMetadata()),
								Active:       trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								CreationDate: trivyTypes.TimeUnresolvable(trivyTypes.NewTestMetadata()),
								LastAccess:   trivyTypes.TimeUnresolvable(trivyTypes.NewTestMetadata()),
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
			testState.AWS.IAM = test.input
			results := checkNoRootAccessKeys.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == checkNoRootAccessKeys.LongID() {
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
