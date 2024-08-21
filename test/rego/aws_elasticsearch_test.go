package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/elasticsearch"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

var awsElasticsearchTestCases = testCases{
	"AVD-AWS-0048": {
		{
			name: "Elasticsearch domain with at-rest encryption disabled",
			input: state.State{AWS: aws.AWS{Elasticsearch: elasticsearch.Elasticsearch{
				Domains: []elasticsearch.Domain{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						AtRestEncryption: elasticsearch.AtRestEncryption{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Elasticsearch domain with at-rest encryption enabled",
			input: state.State{AWS: aws.AWS{Elasticsearch: elasticsearch.Elasticsearch{
				Domains: []elasticsearch.Domain{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						AtRestEncryption: elasticsearch.AtRestEncryption{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0042": {
		{
			name: "Elasticsearch domain with audit logging disabled",
			input: state.State{AWS: aws.AWS{Elasticsearch: elasticsearch.Elasticsearch{
				Domains: []elasticsearch.Domain{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						LogPublishing: elasticsearch.LogPublishing{
							Metadata:     trivyTypes.NewTestMetadata(),
							AuditEnabled: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Elasticsearch domain with audit logging enabled",
			input: state.State{AWS: aws.AWS{Elasticsearch: elasticsearch.Elasticsearch{
				Domains: []elasticsearch.Domain{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						LogPublishing: elasticsearch.LogPublishing{
							Metadata:     trivyTypes.NewTestMetadata(),
							AuditEnabled: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0043": {
		{
			name: "Elasticsearch domain without in-transit encryption",
			input: state.State{AWS: aws.AWS{Elasticsearch: elasticsearch.Elasticsearch{
				Domains: []elasticsearch.Domain{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						TransitEncryption: elasticsearch.TransitEncryption{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Elasticsearch domain with in-transit encryption",
			input: state.State{AWS: aws.AWS{Elasticsearch: elasticsearch.Elasticsearch{
				Domains: []elasticsearch.Domain{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						TransitEncryption: elasticsearch.TransitEncryption{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0046": {
		{
			name: "Elasticsearch domain with enforce HTTPS disabled",
			input: state.State{AWS: aws.AWS{Elasticsearch: elasticsearch.Elasticsearch{
				Domains: []elasticsearch.Domain{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Endpoint: elasticsearch.Endpoint{
							Metadata:     trivyTypes.NewTestMetadata(),
							EnforceHTTPS: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Elasticsearch domain with enforce HTTPS enabled",
			input: state.State{AWS: aws.AWS{Elasticsearch: elasticsearch.Elasticsearch{
				Domains: []elasticsearch.Domain{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Endpoint: elasticsearch.Endpoint{
							Metadata:     trivyTypes.NewTestMetadata(),
							EnforceHTTPS: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0126": {
		{
			name: "Elasticsearch domain with TLS v1.0",
			input: state.State{AWS: aws.AWS{Elasticsearch: elasticsearch.Elasticsearch{
				Domains: []elasticsearch.Domain{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Endpoint: elasticsearch.Endpoint{
							Metadata:  trivyTypes.NewTestMetadata(),
							TLSPolicy: trivyTypes.String("Policy-Min-TLS-1-0-2019-07", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Elasticsearch domain with TLS v1.2",
			input: state.State{AWS: aws.AWS{Elasticsearch: elasticsearch.Elasticsearch{
				Domains: []elasticsearch.Domain{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Endpoint: elasticsearch.Endpoint{
							Metadata:  trivyTypes.NewTestMetadata(),
							TLSPolicy: trivyTypes.String("Policy-Min-TLS-1-2-2019-07", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
