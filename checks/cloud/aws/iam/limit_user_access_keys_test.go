package iam

import (
	"testing"
	"time"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckLimitUserAccessKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "Single active access key",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Name:       trivyTypes.String("user", trivyTypes.NewTestMetadata()),
						LastAccess: trivyTypes.TimeUnresolvable(trivyTypes.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     trivyTypes.NewTestMetadata(),
								AccessKeyId:  trivyTypes.String("AKIACKCEVSQ6C2EXAMPLE", trivyTypes.NewTestMetadata()),
								Active:       trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								CreationDate: trivyTypes.Time(time.Now().Add(-time.Hour*24*30), trivyTypes.NewTestMetadata()),
								LastAccess:   trivyTypes.Time(time.Now(), trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "One active, one inactive access key",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Name:       trivyTypes.String("user", trivyTypes.NewTestMetadata()),
						LastAccess: trivyTypes.TimeUnresolvable(trivyTypes.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     trivyTypes.NewTestMetadata(),
								AccessKeyId:  trivyTypes.String("AKIACKCEVSQ6C2EXAMPLE", trivyTypes.NewTestMetadata()),
								Active:       trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								CreationDate: trivyTypes.Time(time.Now().Add(-time.Hour*24*30), trivyTypes.NewTestMetadata()),
								LastAccess:   trivyTypes.Time(time.Now(), trivyTypes.NewTestMetadata()),
							},
							{
								Metadata:     trivyTypes.NewTestMetadata(),
								AccessKeyId:  trivyTypes.String("AKIACKCEVSQ6C2EXAMPLE", trivyTypes.NewTestMetadata()),
								Active:       trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								CreationDate: trivyTypes.Time(time.Now().Add(-time.Hour*24*30), trivyTypes.NewTestMetadata()),
								LastAccess:   trivyTypes.Time(time.Now(), trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Two inactive keys",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Name:       trivyTypes.String("user", trivyTypes.NewTestMetadata()),
						LastAccess: trivyTypes.TimeUnresolvable(trivyTypes.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     trivyTypes.NewTestMetadata(),
								AccessKeyId:  trivyTypes.String("AKIACKCEVSQ6C2EXAMPLE", trivyTypes.NewTestMetadata()),
								Active:       trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								CreationDate: trivyTypes.Time(time.Now().Add(-time.Hour*24*30), trivyTypes.NewTestMetadata()),
								LastAccess:   trivyTypes.Time(time.Now(), trivyTypes.NewTestMetadata()),
							},
							{
								Metadata:     trivyTypes.NewTestMetadata(),
								AccessKeyId:  trivyTypes.String("AKIACKCEVSQ6C2EXAMPLE", trivyTypes.NewTestMetadata()),
								Active:       trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								CreationDate: trivyTypes.Time(time.Now().Add(-time.Hour*24*30), trivyTypes.NewTestMetadata()),
								LastAccess:   trivyTypes.Time(time.Now(), trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Two active keys",
			input: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Name:       trivyTypes.String("user", trivyTypes.NewTestMetadata()),
						LastAccess: trivyTypes.TimeUnresolvable(trivyTypes.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     trivyTypes.NewTestMetadata(),
								AccessKeyId:  trivyTypes.String("AKIACKCEVSQ6C2EXAMPLE", trivyTypes.NewTestMetadata()),
								Active:       trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								CreationDate: trivyTypes.Time(time.Now().Add(-time.Hour*24*30), trivyTypes.NewTestMetadata()),
								LastAccess:   trivyTypes.Time(time.Now(), trivyTypes.NewTestMetadata()),
							},
							{
								Metadata:     trivyTypes.NewTestMetadata(),
								AccessKeyId:  trivyTypes.String("AKIACKCEVSQ6C2EXAMPLE", trivyTypes.NewTestMetadata()),
								Active:       trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								CreationDate: trivyTypes.Time(time.Now().Add(-time.Hour*24*30), trivyTypes.NewTestMetadata()),
								LastAccess:   trivyTypes.Time(time.Now(), trivyTypes.NewTestMetadata()),
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
			results := CheckLimitUserAccessKeys.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckLimitUserAccessKeys.LongID() {
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
