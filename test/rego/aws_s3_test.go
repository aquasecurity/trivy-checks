package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/cloudtrail"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/s3"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(awsS3TestCases)
}

var awsS3TestCases = testCases{
	"AVD-AWS-0086": {
		{
			name: "Public access block missing",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Public access block blocks public ACLs",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						PublicAccessBlock: &s3.PublicAccessBlock{
							Metadata:        trivyTypes.NewTestMetadata(),
							BlockPublicACLs: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0087": {
		{
			name: "Public access block missing",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Public access block blocks public policies",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						PublicAccessBlock: &s3.PublicAccessBlock{
							Metadata:          trivyTypes.NewTestMetadata(),
							BlockPublicPolicy: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0088": {
		{
			name: "Bucket encryption disabled",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: s3.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Bucket encryption enabled",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: s3.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0172": {
		{
			name: "S3 bucket with no cloudtrail logging",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Name:     trivyTypes.String("test-bucket", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "S3 bucket with WriteOnly cloudtrail logging (all of s3)",
			input: state.State{AWS: aws.AWS{
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Name:     trivyTypes.String("test-bucket", trivyTypes.NewTestMetadata()),
						},
					}},
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							EventSelectors: []cloudtrail.EventSelector{
								{
									Metadata:      trivyTypes.NewTestMetadata(),
									ReadWriteType: trivyTypes.String("WriteOnly", trivyTypes.NewTestMetadata()),
									DataResources: []cloudtrail.DataResource{
										{
											Metadata: trivyTypes.NewTestMetadata(),
											Type:     trivyTypes.String("AWS::S3::Object", trivyTypes.NewTestMetadata()),
											Values: []trivyTypes.StringValue{
												trivyTypes.String("arn:aws:s3", trivyTypes.NewTestMetadata()),
											},
										},
									},
								},
							},
						},
					},
				}},
			},
			expected: true,
		},
		{
			name: "S3 bucket with ReadOnly cloudtrail logging (all of s3)",
			input: state.State{AWS: aws.AWS{
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Name:     trivyTypes.String("test-bucket", trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							EventSelectors: []cloudtrail.EventSelector{
								{
									Metadata:      trivyTypes.NewTestMetadata(),
									ReadWriteType: trivyTypes.String("ReadOnly", trivyTypes.NewTestMetadata()),
									DataResources: []cloudtrail.DataResource{
										{
											Metadata: trivyTypes.NewTestMetadata(),
											Type:     trivyTypes.String("AWS::S3::Object", trivyTypes.NewTestMetadata()),
											Values: []trivyTypes.StringValue{
												trivyTypes.String("arn:aws:s3", trivyTypes.NewTestMetadata()),
											},
										},
									},
								},
							},
						},
					},
				}},
			},
			expected: false,
		},
		{
			name: "S3 bucket with 'All' cloudtrail logging (all of s3)",
			input: state.State{AWS: aws.AWS{
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Name:     trivyTypes.String("test-bucket", trivyTypes.NewTestMetadata()),
						},
					}},
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							EventSelectors: []cloudtrail.EventSelector{
								{
									Metadata:      trivyTypes.NewTestMetadata(),
									ReadWriteType: trivyTypes.String("All", trivyTypes.NewTestMetadata()),
									DataResources: []cloudtrail.DataResource{
										{
											Metadata: trivyTypes.NewTestMetadata(),
											Type:     trivyTypes.String("AWS::S3::Object", trivyTypes.NewTestMetadata()),
											Values: []trivyTypes.StringValue{
												trivyTypes.String("arn:aws:s3", trivyTypes.NewTestMetadata()),
											},
										},
									},
								},
							},
						},
					},
				}},
			},
			expected: false,
		},
		{
			name: "S3 bucket with 'All' cloudtrail logging (only this bucket)",
			input: state.State{AWS: aws.AWS{
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Name:     trivyTypes.String("test-bucket", trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							EventSelectors: []cloudtrail.EventSelector{
								{
									Metadata:      trivyTypes.NewTestMetadata(),
									ReadWriteType: trivyTypes.String("All", trivyTypes.NewTestMetadata()),
									DataResources: []cloudtrail.DataResource{
										{
											Metadata: trivyTypes.NewTestMetadata(),
											Type:     trivyTypes.String("AWS::S3::Object", trivyTypes.NewTestMetadata()),
											Values: []trivyTypes.StringValue{
												trivyTypes.String("arn:aws:s3:::test-bucket/", trivyTypes.NewTestMetadata()),
											},
										},
									},
								},
							},
						},
					},
				}},
			},
			expected: false,
		},
		{
			name: "S3 bucket with 'All' cloudtrail logging (only another bucket)",
			input: state.State{AWS: aws.AWS{
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Name:     trivyTypes.String("test-bucket", trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							EventSelectors: []cloudtrail.EventSelector{
								{
									Metadata:      trivyTypes.NewTestMetadata(),
									ReadWriteType: trivyTypes.String("All", trivyTypes.NewTestMetadata()),
									DataResources: []cloudtrail.DataResource{
										{
											Metadata: trivyTypes.NewTestMetadata(),
											Type:     trivyTypes.String("AWS::S3::Object", trivyTypes.NewTestMetadata()),
											Values: []trivyTypes.StringValue{
												trivyTypes.String("arn:aws:s3:::test-bucket2/", trivyTypes.NewTestMetadata()),
											},
										},
									},
								},
							},
						},
					},
				}}},
			expected: true,
		},
		{
			name: "S3 bucket with 'All' cloudtrail logging (this bucket, missing slash)",
			input: state.State{AWS: aws.AWS{
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Name:     trivyTypes.String("test-bucket", trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							EventSelectors: []cloudtrail.EventSelector{
								{
									Metadata:      trivyTypes.NewTestMetadata(),
									ReadWriteType: trivyTypes.String("All", trivyTypes.NewTestMetadata()),
									DataResources: []cloudtrail.DataResource{
										{
											Metadata: trivyTypes.NewTestMetadata(),
											Type:     trivyTypes.String("AWS::S3::Object", trivyTypes.NewTestMetadata()),
											Values: []trivyTypes.StringValue{
												trivyTypes.String("arn:aws:s3:::test-bucket", trivyTypes.NewTestMetadata()),
											},
										},
									},
								},
							},
						},
					},
				}},
			},
			expected: true,
		},
	},
	"AVD-AWS-0171": {
		{
			name: "S3 bucket with no cloudtrail logging",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Name:     trivyTypes.String("test-bucket", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "S3 bucket with ReadOnly cloudtrail logging (all of s3)",
			input: state.State{AWS: aws.AWS{
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Name:     trivyTypes.String("test-bucket", trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							EventSelectors: []cloudtrail.EventSelector{
								{
									Metadata:      trivyTypes.NewTestMetadata(),
									ReadWriteType: trivyTypes.String("ReadOnly", trivyTypes.NewTestMetadata()),
									DataResources: []cloudtrail.DataResource{
										{
											Metadata: trivyTypes.NewTestMetadata(),
											Type:     trivyTypes.String("AWS::S3::Object", trivyTypes.NewTestMetadata()),
											Values: []trivyTypes.StringValue{
												trivyTypes.String("arn:aws:s3", trivyTypes.NewTestMetadata()),
											},
										},
									},
								},
							},
						},
					},
				},
			}},
			expected: true,
		},
		{
			name: "S3 bucket with WriteOnly cloudtrail logging (all of s3)",
			input: state.State{AWS: aws.AWS{
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Name:     trivyTypes.String("test-bucket", trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							EventSelectors: []cloudtrail.EventSelector{
								{
									Metadata:      trivyTypes.NewTestMetadata(),
									ReadWriteType: trivyTypes.String("WriteOnly", trivyTypes.NewTestMetadata()),
									DataResources: []cloudtrail.DataResource{
										{
											Metadata: trivyTypes.NewTestMetadata(),
											Type:     trivyTypes.String("AWS::S3::Object", trivyTypes.NewTestMetadata()),
											Values: []trivyTypes.StringValue{
												trivyTypes.String("arn:aws:s3", trivyTypes.NewTestMetadata()),
											},
										},
									},
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "S3 bucket with 'All' cloudtrail logging (all of s3)",
			input: state.State{AWS: aws.AWS{
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Name:     trivyTypes.String("test-bucket", trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							EventSelectors: []cloudtrail.EventSelector{
								{
									Metadata:      trivyTypes.NewTestMetadata(),
									ReadWriteType: trivyTypes.String("All", trivyTypes.NewTestMetadata()),
									DataResources: []cloudtrail.DataResource{
										{
											Metadata: trivyTypes.NewTestMetadata(),
											Type:     trivyTypes.String("AWS::S3::Object", trivyTypes.NewTestMetadata()),
											Values: []trivyTypes.StringValue{
												trivyTypes.String("arn:aws:s3", trivyTypes.NewTestMetadata()),
											},
										},
									},
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "S3 bucket with 'All' cloudtrail logging (only this bucket)",
			input: state.State{AWS: aws.AWS{
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Name:     trivyTypes.String("test-bucket", trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							EventSelectors: []cloudtrail.EventSelector{
								{
									Metadata:      trivyTypes.NewTestMetadata(),
									ReadWriteType: trivyTypes.String("All", trivyTypes.NewTestMetadata()),
									DataResources: []cloudtrail.DataResource{
										{
											Metadata: trivyTypes.NewTestMetadata(),
											Type:     trivyTypes.String("AWS::S3::Object", trivyTypes.NewTestMetadata()),
											Values: []trivyTypes.StringValue{
												trivyTypes.String("arn:aws:s3:::test-bucket/", trivyTypes.NewTestMetadata()),
											},
										},
									},
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "S3 bucket with 'All' cloudtrail logging (only another bucket)",
			input: state.State{AWS: aws.AWS{
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Name:     trivyTypes.String("test-bucket", trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							EventSelectors: []cloudtrail.EventSelector{
								{
									Metadata:      trivyTypes.NewTestMetadata(),
									ReadWriteType: trivyTypes.String("All", trivyTypes.NewTestMetadata()),
									DataResources: []cloudtrail.DataResource{
										{
											Metadata: trivyTypes.NewTestMetadata(),
											Type:     trivyTypes.String("AWS::S3::Object", trivyTypes.NewTestMetadata()),
											Values: []trivyTypes.StringValue{
												trivyTypes.String("arn:aws:s3:::test-bucket2/", trivyTypes.NewTestMetadata()),
											},
										},
									},
								},
							},
						},
					},
				},
			}},
			expected: true,
		},
		{
			name: "S3 bucket with 'All' cloudtrail logging (this bucket, missing slash)",
			input: state.State{AWS: aws.AWS{
				S3: s3.S3{
					Buckets: []s3.Bucket{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							Name:     trivyTypes.String("test-bucket", trivyTypes.NewTestMetadata()),
						},
					},
				},
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata: trivyTypes.NewTestMetadata(),
							EventSelectors: []cloudtrail.EventSelector{
								{
									Metadata:      trivyTypes.NewTestMetadata(),
									ReadWriteType: trivyTypes.String("All", trivyTypes.NewTestMetadata()),
									DataResources: []cloudtrail.DataResource{
										{
											Metadata: trivyTypes.NewTestMetadata(),
											Type:     trivyTypes.String("AWS::S3::Object", trivyTypes.NewTestMetadata()),
											Values: []trivyTypes.StringValue{
												trivyTypes.String("arn:aws:s3:::test-bucket", trivyTypes.NewTestMetadata()),
											},
										},
									},
								},
							},
						},
					},
				},
			}},
			expected: true,
		},
	},
	"AVD-AWS-0090": {
		{
			name: "S3 bucket versioning disabled",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Versioning: s3.Versioning{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "S3 bucket versioning enabled",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Versioning: s3.Versioning{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0132": {
		{
			name: "S3 Bucket missing KMS key",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: s3.Encryption{
							Metadata: trivyTypes.Metadata{},
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							KMSKeyId: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "S3 Bucket with KMS key",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: s3.Encryption{
							Metadata: trivyTypes.Metadata{},
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							KMSKeyId: trivyTypes.String("some-sort-of-key", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0091": {
		{
			name: "Public access block missing",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Public access block ignores public ACLs",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						PublicAccessBlock: &s3.PublicAccessBlock{
							Metadata:         trivyTypes.NewTestMetadata(),
							IgnorePublicACLs: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0092": {
		{
			name: "positive result",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ACL:      trivyTypes.String("public-read", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "negative result",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ACL:      trivyTypes.String("private", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0093": {
		{
			name: "Public access block missing",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Public access block limiting access to buckets",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						PublicAccessBlock: &s3.PublicAccessBlock{
							Metadata:              trivyTypes.NewTestMetadata(),
							RestrictPublicBuckets: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0170": {
		{
			name: "RequireMFADelete is not set",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Versioning: s3.Versioning{
							Metadata:  trivyTypes.NewTestMetadata(),
							Enabled:   trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							MFADelete: trivyTypes.BoolDefault(false, trivyTypes.NewUnmanagedMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "RequireMFADelete is false",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Versioning: s3.Versioning{
							Metadata:  trivyTypes.NewTestMetadata(),
							Enabled:   trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							MFADelete: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "RequireMFADelete is true",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Versioning: s3.Versioning{
							Metadata:  trivyTypes.NewTestMetadata(),
							Enabled:   trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							MFADelete: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0094": {
		{
			name: "Public access block missing",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Public access block present",
			input: state.State{AWS: aws.AWS{S3: s3.S3{
				Buckets: []s3.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						PublicAccessBlock: &s3.PublicAccessBlock{
							Metadata: trivyTypes.NewTestMetadata(),
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
