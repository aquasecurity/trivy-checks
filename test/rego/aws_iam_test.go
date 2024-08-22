package test

import (
	"time"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/iam"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
	"github.com/liamg/iamgo"
)

func init() {
	addTests(awsIamTestCases)
}

var awsIamTestCases = testCases{
	"AVD-AWS-0166": {
		{
			name: "User logged in today",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Name:       trivyTypes.String("user", trivyTypes.NewTestMetadata()),
						LastAccess: trivyTypes.Time(time.Now(), trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name: "User never logged in, but used access key today",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
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
			}}},
			expected: false,
		},
		{
			name: "User logged in 50 days ago",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Name:       trivyTypes.String("user", trivyTypes.NewTestMetadata()),
						LastAccess: trivyTypes.Time(time.Now().Add(-time.Hour*24*50), trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "User last used access key 50 days ago but it is no longer active",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
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
								CreationDate: trivyTypes.Time(time.Now().Add(-time.Hour*24*120), trivyTypes.NewTestMetadata()),
								LastAccess:   trivyTypes.Time(time.Now().Add(-time.Hour*24*50), trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "User last used access key 50 days ago and it is active",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
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
								CreationDate: trivyTypes.Time(time.Now().Add(-time.Hour*24*120), trivyTypes.NewTestMetadata()),
								LastAccess:   trivyTypes.Time(time.Now().Add(-time.Hour*24*50), trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
	},
	"AVD-AWS-0144": {
		{
			name: "User logged in today",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Name:       trivyTypes.String("user", trivyTypes.NewTestMetadata()),
						LastAccess: trivyTypes.Time(time.Now(), trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name: "User never logged in, but used access key today",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
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
			}}},
			expected: false,
		},
		{
			name: "User logged in 100 days ago",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Name:       trivyTypes.String("user", trivyTypes.NewTestMetadata()),
						LastAccess: trivyTypes.Time(time.Now().Add(-time.Hour*24*100), trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "User last used access key 100 days ago but it is no longer active",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
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
								CreationDate: trivyTypes.Time(time.Now().Add(-time.Hour*24*120), trivyTypes.NewTestMetadata()),
								LastAccess:   trivyTypes.Time(time.Now().Add(-time.Hour*24*100), trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "User last used access key 100 days ago and it is active",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
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
								CreationDate: trivyTypes.Time(time.Now().Add(-time.Hour*24*120), trivyTypes.NewTestMetadata()),
								LastAccess:   trivyTypes.Time(time.Now().Add(-time.Hour*24*100), trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
	},
	"AVD-AWS-0123": {
		{
			name: "IAM policy with no MFA required",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Groups: []iam.Group{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Policies: []iam.Policy{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Document: func() iam.Document {

									builder := iamgo.NewPolicyBuilder()
									builder.WithVersion("2012-10-17")

									sb := iamgo.NewStatementBuilder()
									sb.WithEffect(iamgo.EffectAllow)
									sb.WithActions([]string{"ec2:*"})

									builder.WithStatement(sb.Build())

									return iam.Document{
										Parsed: builder.Build(),
									}
								}(),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "IAM policy with MFA required",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Groups: []iam.Group{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Policies: []iam.Policy{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Document: func() iam.Document {

									builder := iamgo.NewPolicyBuilder()
									builder.WithVersion("2012-10-17")

									sb := iamgo.NewStatementBuilder()
									sb.WithEffect(iamgo.EffectAllow)
									sb.WithActions([]string{"ec2:*"})
									sb.WithCondition("Bool", "aws:MultiFactorAuthPresent", []string{"true"})

									builder.WithStatement(sb.Build())

									return iam.Document{
										Parsed: builder.Build(),
									}
								}(),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0142": {
		{
			name: "root user without mfa",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Name:     trivyTypes.String("root", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "other user without mfa",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Name:     trivyTypes.String("other", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name: "root user with mfa",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Name:     trivyTypes.String("root", trivyTypes.NewTestMetadata()),
						MFADevices: []iam.MFADevice{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								IsVirtual: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0140": {
		{
			name: "root user, never logged in",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Name:       trivyTypes.String("root", trivyTypes.NewTestMetadata()),
						LastAccess: trivyTypes.TimeUnresolvable(trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name: "root user, logged in months ago",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Name:       trivyTypes.String("other", trivyTypes.NewTestMetadata()),
						LastAccess: trivyTypes.Time(time.Now().Add(-time.Hour*24*90), trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name: "root user, logged in today",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Name:       trivyTypes.String("root", trivyTypes.NewTestMetadata()),
						LastAccess: trivyTypes.Time(time.Now().Add(-time.Hour), trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "other user, logged in today",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Name:       trivyTypes.String("other", trivyTypes.NewTestMetadata()),
						LastAccess: trivyTypes.Time(time.Now().Add(-time.Hour), trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0167": {
		{
			name: "Single active access key",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
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
			}}},
			expected: false,
		},
		{
			name: "One active, one inactive access key",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
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
			}}},
			expected: false,
		},
		{
			name: "Two inactive keys",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
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
			}}},
			expected: false,
		},
		{
			name: "Two active keys",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
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
			}}},
			expected: true,
		},
	},
	"AVD-AWS-0056": {
		{
			name: "IAM with 1 password that can't be reused (min)",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:             trivyTypes.NewTestMetadata(),
					ReusePreventionCount: trivyTypes.Int(1, trivyTypes.NewTestMetadata()),
				},
			}}},
			expected: true,
		},
		{
			name: "IAM with 5 passwords that can't be reused",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:             trivyTypes.NewTestMetadata(),
					ReusePreventionCount: trivyTypes.Int(5, trivyTypes.NewTestMetadata()),
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0141": {
		{
			name: "root user without access key",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Name:       trivyTypes.String("root", trivyTypes.NewTestMetadata()),
						AccessKeys: nil,
					},
				},
			}}},
			expected: false,
		},
		{
			name: "other user without access key",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Name:       trivyTypes.String("other", trivyTypes.NewTestMetadata()),
						AccessKeys: nil,
					},
				},
			}}},
			expected: false,
		},
		{
			name: "other user with access key",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
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
			}}},
			expected: false,
		},
		{
			name: "root user with inactive access key",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
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
			}}},
			expected: false,
		},
		{
			name: "root user with active access key",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
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
			}}},
			expected: true,
		},
	},
	"AVD-AWS-0143": {
		{
			name: "user without policies attached",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Name:     trivyTypes.String("example", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name: "user with a policy attached",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Name:     trivyTypes.String("example", trivyTypes.NewTestMetadata()),
						Policies: []iam.Policy{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Name:     trivyTypes.String("another.policy", trivyTypes.NewTestMetadata()),
								Document: iam.Document{
									Metadata: trivyTypes.NewTestMetadata(),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
	},
	"AVD-AWS-0168": {
		{
			name:     "No certs",
			input:    state.State{AWS: aws.AWS{IAM: iam.IAM{}}},
			expected: false,
		},
		{
			name: "Valid cert",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				ServerCertificates: []iam.ServerCertificate{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Expiration: trivyTypes.Time(time.Now().Add(time.Hour), trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Expired cert",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				ServerCertificates: []iam.ServerCertificate{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Expiration: trivyTypes.Time(time.Now().Add(-time.Hour), trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
	},
	"AVD-AWS-0058": {
		{
			name: "IAM password policy lowercase not required",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:         trivyTypes.NewTestMetadata(),
					RequireLowercase: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
				},
			}}},
			expected: true,
		},
		{
			name: "IAM password policy lowercase required",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:         trivyTypes.NewTestMetadata(),
					RequireLowercase: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0059": {
		{
			name: "IAM password policy numbers not required",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:       trivyTypes.NewTestMetadata(),
					RequireNumbers: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
				},
			}}},
			expected: true,
		},
		{
			name: "IAM password policy numbers required",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:       trivyTypes.NewTestMetadata(),
					RequireNumbers: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0060": {
		{
			name: "IAM password policy symbols not required",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:       trivyTypes.NewTestMetadata(),
					RequireSymbols: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
				},
			}}},
			expected: true,
		},
		{
			name: "IAM password policy symbols required",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:       trivyTypes.NewTestMetadata(),
					RequireSymbols: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0061": {
		{
			name: "IAM password policy uppercase not required",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:         trivyTypes.NewTestMetadata(),
					RequireUppercase: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
				},
			}}},
			expected: true,
		},
		{
			name: "IAM password policy uppercase required",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:         trivyTypes.NewTestMetadata(),
					RequireUppercase: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0146": {
		{
			name: "Access key created a month ago",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
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
			}}},
			expected: false,
		},
		{
			name: "Access key created 4 months ago",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
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
								CreationDate: trivyTypes.Time(time.Now().Add(-time.Hour*24*30*4), trivyTypes.NewTestMetadata()),
								LastAccess:   trivyTypes.Time(time.Now(), trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
	},
	"AVD-AWS-0062": {
		{
			name: "Password expires in 99 days",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:   trivyTypes.NewTestMetadata(),
					MaxAgeDays: trivyTypes.Int(99, trivyTypes.NewTestMetadata()),
				},
			}}},
			expected: true,
		},
		{
			name: "Password expires in 60 days",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:   trivyTypes.NewTestMetadata(),
					MaxAgeDays: trivyTypes.Int(60, trivyTypes.NewTestMetadata()),
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0063": {
		{
			name: "Minimum password length set to 8",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:      trivyTypes.NewTestMetadata(),
					MinimumLength: trivyTypes.Int(8, trivyTypes.NewTestMetadata()),
				},
			}}},
			expected: true,
		},
		{
			name: "Minimum password length set to 15",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:      trivyTypes.NewTestMetadata(),
					MinimumLength: trivyTypes.Int(15, trivyTypes.NewTestMetadata()),
				},
			}}},
			expected: false,
		},
	},
}
