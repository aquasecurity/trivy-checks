package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/msk"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(awsMskTestCases)
}

var awsMskTestCases = testCases{
	"AVD-AWS-0179": {
		{
			name: "Cluster with at rest encryption enabled",
			input: state.State{AWS: aws.AWS{MSK: msk.MSK{
				Clusters: []msk.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						EncryptionAtRest: msk.EncryptionAtRest{
							Metadata:  trivyTypes.NewTestMetadata(),
							KMSKeyARN: trivyTypes.String("foo-bar-key", trivyTypes.NewTestMetadata()),
							Enabled:   trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Cluster with at rest encryption disabled",
			input: state.State{AWS: aws.AWS{MSK: msk.MSK{
				Clusters: []msk.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
					},
				},
			}}},
			expected: true,
		},
	},
	"AVD-AWS-0073": {
		{
			name: "Cluster client broker with plaintext encryption",
			input: state.State{AWS: aws.AWS{MSK: msk.MSK{
				Clusters: []msk.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						EncryptionInTransit: msk.EncryptionInTransit{
							Metadata:     trivyTypes.NewTestMetadata(),
							ClientBroker: trivyTypes.String(msk.ClientBrokerEncryptionPlaintext, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster client broker with plaintext or TLS encryption",
			input: state.State{AWS: aws.AWS{MSK: msk.MSK{
				Clusters: []msk.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						EncryptionInTransit: msk.EncryptionInTransit{
							Metadata:     trivyTypes.NewTestMetadata(),
							ClientBroker: trivyTypes.String(msk.ClientBrokerEncryptionTLSOrPlaintext, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster client broker with TLS encryption",
			input: state.State{AWS: aws.AWS{MSK: msk.MSK{
				Clusters: []msk.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						EncryptionInTransit: msk.EncryptionInTransit{
							Metadata:     trivyTypes.NewTestMetadata(),
							ClientBroker: trivyTypes.String(msk.ClientBrokerEncryptionTLS, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0074": {
		{
			name: "Cluster with logging disabled",
			input: state.State{AWS: aws.AWS{MSK: msk.MSK{
				Clusters: []msk.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Logging: msk.Logging{
							Metadata: trivyTypes.NewTestMetadata(),
							Broker: msk.BrokerLogging{
								Metadata: trivyTypes.NewTestMetadata(),
								S3: msk.S3Logging{
									Metadata: trivyTypes.NewTestMetadata(),
									Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								},
								Cloudwatch: msk.CloudwatchLogging{
									Metadata: trivyTypes.NewTestMetadata(),
									Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								},
								Firehose: msk.FirehoseLogging{
									Metadata: trivyTypes.NewTestMetadata(),
									Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster logging to S3",
			input: state.State{AWS: aws.AWS{MSK: msk.MSK{
				Clusters: []msk.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Logging: msk.Logging{
							Metadata: trivyTypes.NewTestMetadata(),
							Broker: msk.BrokerLogging{
								Metadata: trivyTypes.NewTestMetadata(),
								S3: msk.S3Logging{
									Metadata: trivyTypes.NewTestMetadata(),
									Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								},
								Cloudwatch: msk.CloudwatchLogging{
									Metadata: trivyTypes.NewTestMetadata(),
									Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								},
								Firehose: msk.FirehoseLogging{
									Metadata: trivyTypes.NewTestMetadata(),
									Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
