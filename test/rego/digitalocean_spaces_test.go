package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/digitalocean"
	"github.com/aquasecurity/trivy/pkg/iac/providers/digitalocean/spaces"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

var digitalOceanSpacesTestCases = testCases{
	"AVD-DIG-0006": {
		{
			name: "Space bucket with public read ACL",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Spaces: spaces.Spaces{
				Buckets: []spaces.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ACL:      trivyTypes.String("public-read", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Space bucket object with public read ACL",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Spaces: spaces.Spaces{
				Buckets: []spaces.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ACL:      trivyTypes.String("private", trivyTypes.NewTestMetadata()),
						Objects: []spaces.Object{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								ACL:      trivyTypes.String("public-read", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Space bucket and bucket object with private ACL",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Spaces: spaces.Spaces{
				Buckets: []spaces.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ACL:      trivyTypes.String("private", trivyTypes.NewTestMetadata()),
						Objects: []spaces.Object{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								ACL:      trivyTypes.String("private", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-DIG-0009": {
		{
			name: "Space bucket force destroy enabled",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Spaces: spaces.Spaces{
				Buckets: []spaces.Bucket{
					{
						Metadata:     trivyTypes.NewTestMetadata(),
						ForceDestroy: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Space bucket force destroy disabled",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Spaces: spaces.Spaces{
				Buckets: []spaces.Bucket{
					{
						Metadata:     trivyTypes.NewTestMetadata(),
						ForceDestroy: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-DIG-0007": {
		{
			name: "Space bucket versioning disabled",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Spaces: spaces.Spaces{
				Buckets: []spaces.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Versioning: spaces.Versioning{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Space bucket versioning enabled",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Spaces: spaces.Spaces{
				Buckets: []spaces.Bucket{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Versioning: spaces.Versioning{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
