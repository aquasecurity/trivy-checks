package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/cloudfront"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(awsCloudfrontTestCases)
}

var awsCloudfrontTestCases = testCases{
	"AVD-AWS-0010": {
		{
			name: "CloudFront distribution missing logging configuration",
			input: state.State{AWS: aws.AWS{Cloudfront: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Logging: cloudfront.Logging{
							Metadata: trivyTypes.NewTestMetadata(),
							Bucket:   trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "CloudFront distribution with logging configured",
			input: state.State{AWS: aws.AWS{Cloudfront: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Logging: cloudfront.Logging{
							Metadata: trivyTypes.NewTestMetadata(),
							Bucket:   trivyTypes.String("mylogs.s3.amazonaws.com", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0011": {
		{
			name: "CloudFront distribution missing WAF",
			input: state.State{AWS: aws.AWS{Cloudfront: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						WAFID:    trivyTypes.String("", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "CloudFront distribution with WAF provided",
			input: state.State{AWS: aws.AWS{Cloudfront: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						WAFID:    trivyTypes.String("waf_id", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0012": {
		{
			name: "CloudFront distribution default cache behaviour with allow all policy",
			input: state.State{AWS: aws.AWS{Cloudfront: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						DefaultCacheBehaviour: cloudfront.CacheBehaviour{
							Metadata:             trivyTypes.NewTestMetadata(),
							ViewerProtocolPolicy: trivyTypes.String(cloudfront.ViewerPolicyProtocolAllowAll, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "CloudFront distribution ordered cache behaviour with allow all policy",
			input: state.State{AWS: aws.AWS{Cloudfront: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						DefaultCacheBehaviour: cloudfront.CacheBehaviour{
							Metadata:             trivyTypes.NewTestMetadata(),
							ViewerProtocolPolicy: trivyTypes.String(cloudfront.ViewerPolicyProtocolHTTPSOnly, trivyTypes.NewTestMetadata()),
						},
						OrdererCacheBehaviours: []cloudfront.CacheBehaviour{
							{
								Metadata:             trivyTypes.NewTestMetadata(),
								ViewerProtocolPolicy: trivyTypes.String(cloudfront.ViewerPolicyProtocolAllowAll, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "CloudFront distribution cache behaviours allowing HTTPS only",
			input: state.State{AWS: aws.AWS{Cloudfront: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						DefaultCacheBehaviour: cloudfront.CacheBehaviour{
							Metadata:             trivyTypes.NewTestMetadata(),
							ViewerProtocolPolicy: trivyTypes.String(cloudfront.ViewerPolicyProtocolHTTPSOnly, trivyTypes.NewTestMetadata()),
						},
						OrdererCacheBehaviours: []cloudfront.CacheBehaviour{
							{
								Metadata:             trivyTypes.NewTestMetadata(),
								ViewerProtocolPolicy: trivyTypes.String(cloudfront.ViewerPolicyProtocolHTTPSOnly, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0013": {
		{
			name: "CloudFront distribution using TLS v1.0",
			input: state.State{AWS: aws.AWS{Cloudfront: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ViewerCertificate: cloudfront.ViewerCertificate{
							Metadata:               trivyTypes.NewTestMetadata(),
							MinimumProtocolVersion: trivyTypes.String("TLSv1.0", trivyTypes.NewTestMetadata()),
							SSLSupportMethod:       trivyTypes.String("sni-only", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "CloudFront distribution using TLS v1.2",
			input: state.State{AWS: aws.AWS{Cloudfront: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ViewerCertificate: cloudfront.ViewerCertificate{
							Metadata:               trivyTypes.NewTestMetadata(),
							MinimumProtocolVersion: trivyTypes.String(cloudfront.ProtocolVersionTLS1_2, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "CloudFrontDefaultCertificate is true",
			input: state.State{AWS: aws.AWS{Cloudfront: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ViewerCertificate: cloudfront.ViewerCertificate{
							Metadata:                     trivyTypes.NewTestMetadata(),
							MinimumProtocolVersion:       trivyTypes.String("TLSv1.0", trivyTypes.NewTestMetadata()),
							CloudfrontDefaultCertificate: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "SSLSupportMethod is not `sny-only`",
			input: state.State{AWS: aws.AWS{Cloudfront: cloudfront.Cloudfront{
				Distributions: []cloudfront.Distribution{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ViewerCertificate: cloudfront.ViewerCertificate{
							Metadata:               trivyTypes.NewTestMetadata(),
							MinimumProtocolVersion: trivyTypes.String("TLSv1.0", trivyTypes.NewTestMetadata()),
							SSLSupportMethod:       trivyTypes.String("vip", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
	},
}
