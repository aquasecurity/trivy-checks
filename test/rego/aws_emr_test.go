package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/emr"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

var awsEmrTestCases = testCases{
	"AVD-AWS-0137": {
		{
			name: "EMR cluster with at-rest encryption disabled",
			input: state.State{AWS: aws.AWS{EMR: emr.EMR{
				SecurityConfiguration: []emr.SecurityConfiguration{
					{
						Name: trivyTypes.String("test", trivyTypes.NewTestMetadata()),
						Configuration: trivyTypes.String(`{
							"EncryptionConfiguration": {
							  "AtRestEncryptionConfiguration": {
								"S3EncryptionConfiguration": {
								  "EncryptionMode": "SSE-S3"
								},
								"LocalDiskEncryptionConfiguration": {
								  "EncryptionKeyProviderType": "AwsKms",
								  "AwsKmsKey": "arn:aws:kms:us-west-2:187416307283:alias/tf_emr_test_key"
								}
							  },
							  "EnableAtRestEncryption": false
							}
						  }`, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "EMR cluster with at-rest encryption enabled",
			input: state.State{AWS: aws.AWS{EMR: emr.EMR{
				SecurityConfiguration: []emr.SecurityConfiguration{
					{
						Name: trivyTypes.String("test", trivyTypes.NewTestMetadata()),
						Configuration: trivyTypes.String(`{
							"EncryptionConfiguration": {
							  "AtRestEncryptionConfiguration": {
								"S3EncryptionConfiguration": {
								  "EncryptionMode": "SSE-S3"
								},
								"LocalDiskEncryptionConfiguration": {
								  "EncryptionKeyProviderType": "AwsKms",
								  "AwsKmsKey": "arn:aws:kms:us-west-2:187416307283:alias/tf_emr_test_key"
								}
							  },
							  "EnableAtRestEncryption": true
							}
						  }`, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0138": {
		{
			name: "EMR cluster with in-transit encryption disabled",
			input: state.State{AWS: aws.AWS{EMR: emr.EMR{
				SecurityConfiguration: []emr.SecurityConfiguration{
					{
						Name: trivyTypes.String("test", trivyTypes.NewTestMetadata()),
						Configuration: trivyTypes.String(`{
							"EncryptionConfiguration": {
							  "AtRestEncryptionConfiguration": {
								"S3EncryptionConfiguration": {
								  "EncryptionMode": "SSE-S3"
								},
								"LocalDiskEncryptionConfiguration": {
								  "EncryptionKeyProviderType": "AwsKms",
								  "AwsKmsKey": "arn:aws:kms:us-west-2:187416307283:alias/tf_emr_test_key"
								}
							  },
							  "EnableInTransitEncryption": false,
							  "EnableAtRestEncryption": false
							}
						  }`, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "EMR cluster with in-transit encryption enabled",
			input: state.State{AWS: aws.AWS{EMR: emr.EMR{
				SecurityConfiguration: []emr.SecurityConfiguration{
					{
						Name: trivyTypes.String("test", trivyTypes.NewTestMetadata()),
						Configuration: trivyTypes.String(`{
							"EncryptionConfiguration": {
							  "AtRestEncryptionConfiguration": {
								"S3EncryptionConfiguration": {
								  "EncryptionMode": "SSE-S3"
								},
								"LocalDiskEncryptionConfiguration": {
								  "EncryptionKeyProviderType": "AwsKms",
								  "AwsKmsKey": "arn:aws:kms:us-west-2:187416307283:alias/tf_emr_test_key"
								}
							  },
							  "EnableInTransitEncryption": true,
							  "EnableAtRestEncryption": true
							}
						  }`, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0139": {
		{
			name: "EMR cluster with local-disk encryption disabled",
			input: state.State{AWS: aws.AWS{EMR: emr.EMR{
				SecurityConfiguration: []emr.SecurityConfiguration{
					{
						Name: trivyTypes.String("test", trivyTypes.NewTestMetadata()),
						Configuration: trivyTypes.String(`{
							"EncryptionConfiguration": {
							  "AtRestEncryptionConfiguration": {
								"S3EncryptionConfiguration": {
								  "EncryptionMode": "SSE-S3"
								},
								"LocalDiskEncryptionConfiguration": {
								  "EncryptionKeyProviderType": "",
								  "AwsKmsKey": ""
								}
							  },
							  "EnableInTransitEncryption": true,
							  "EnableAtRestEncryption": true
							}
						  }`, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "EMR cluster with local-disk encryption enabled",
			input: state.State{AWS: aws.AWS{EMR: emr.EMR{
				SecurityConfiguration: []emr.SecurityConfiguration{
					{
						Name: trivyTypes.String("test", trivyTypes.NewTestMetadata()),
						Configuration: trivyTypes.String(`{
							"EncryptionConfiguration": {
							  "AtRestEncryptionConfiguration": {
								"S3EncryptionConfiguration": {
								  "EncryptionMode": "SSE-S3"
								},
								"LocalDiskEncryptionConfiguration": {
								  "EncryptionKeyProviderType": "AwsKms",
								  "AwsKmsKey": "arn:aws:kms:us-west-2:187416307283:alias/tf_emr_test_key"
								}
							  },
							  "EnableInTransitEncryption": true,
							  "EnableAtRestEncryption": true
							}
						  }`, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
