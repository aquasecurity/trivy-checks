package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/mq"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(awsMqTestCases)
}

var awsMqTestCases = testCases{
	"AVD-AWS-0070": {
		{
			name: "AWS MQ Broker without audit logging",
			input: state.State{AWS: aws.AWS{MQ: mq.MQ{
				Brokers: []mq.Broker{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Logging: mq.Logging{
							Metadata: trivyTypes.NewTestMetadata(),
							Audit:    trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS MQ Broker with audit logging",
			input: state.State{AWS: aws.AWS{MQ: mq.MQ{
				Brokers: []mq.Broker{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Logging: mq.Logging{
							Metadata: trivyTypes.NewTestMetadata(),
							Audit:    trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0071": {
		{
			name: "AWS MQ Broker without general logging",
			input: state.State{AWS: aws.AWS{MQ: mq.MQ{
				Brokers: []mq.Broker{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Logging: mq.Logging{
							Metadata: trivyTypes.NewTestMetadata(),
							General:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS MQ Broker with general logging",
			input: state.State{AWS: aws.AWS{MQ: mq.MQ{
				Brokers: []mq.Broker{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Logging: mq.Logging{
							Metadata: trivyTypes.NewTestMetadata(),
							General:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0072": {
		{
			name: "AWS MQ Broker with public access enabled",
			input: state.State{AWS: aws.AWS{MQ: mq.MQ{
				Brokers: []mq.Broker{
					{
						Metadata:     trivyTypes.NewTestMetadata(),
						PublicAccess: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS MQ Broker with public access disabled",
			input: state.State{AWS: aws.AWS{MQ: mq.MQ{
				Brokers: []mq.Broker{
					{
						Metadata:     trivyTypes.NewTestMetadata(),
						PublicAccess: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
