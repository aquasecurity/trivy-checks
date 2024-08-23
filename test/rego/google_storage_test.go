package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/google"
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/iam"
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/storage"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(googleStorageTestCases)
}

var googleStorageTestCases = testCases{
	"AVD-GCP-0066": {
		{
			name: "Storage bucket missing default kms key name",
			input: state.State{Google: google.Google{Storage: storage.Storage{
				Buckets: []storage.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: storage.BucketEncryption{
							Metadata:          trivyTypes.NewTestMetadata(),
							DefaultKMSKeyName: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Storage bucket with default kms key name provided",
			input: state.State{Google: google.Google{Storage: storage.Storage{
				Buckets: []storage.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: storage.BucketEncryption{
							Metadata:          trivyTypes.NewTestMetadata(),
							DefaultKMSKeyName: trivyTypes.String("default-kms-key-name", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0002": {
		{
			name: "Uniform bucket level access disabled",
			input: state.State{Google: google.Google{Storage: storage.Storage{
				Buckets: []storage.Bucket{
					{
						Metadata:                       trivyTypes.NewTestMetadata(),
						EnableUniformBucketLevelAccess: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Uniform bucket level access enabled",
			input: state.State{Google: google.Google{Storage: storage.Storage{
				Buckets: []storage.Bucket{
					{
						Metadata:                       trivyTypes.NewTestMetadata(),
						EnableUniformBucketLevelAccess: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0001": {
		{
			name: "Members set to all authenticated users",
			input: state.State{Google: google.Google{Storage: storage.Storage{
				Buckets: []storage.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Bindings: []iam.Binding{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Members: []trivyTypes.StringValue{
									trivyTypes.String("allAuthenticatedUsers", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Members set to all users",
			input: state.State{Google: google.Google{Storage: storage.Storage{
				Buckets: []storage.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Members: []iam.Member{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Member:   trivyTypes.String("allUsers", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Members set to specific users",
			input: state.State{Google: google.Google{Storage: storage.Storage{
				Buckets: []storage.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Bindings: []iam.Binding{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Members: []trivyTypes.StringValue{
									trivyTypes.String("user:jane@example.com", trivyTypes.NewTestMetadata()),
								},
							},
						},
						Members: []iam.Member{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Member:   trivyTypes.String("user:john@example.com", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
