package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/sam"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(awsSamTestCases)
}

var awsSamTestCases = testCases{
	"AVD-AWS-0112": {
		{
			name: "SAM API TLS v1.0",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				APIs: []sam.API{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						DomainConfiguration: sam.DomainConfiguration{
							Metadata:       trivyTypes.NewTestMetadata(),
							SecurityPolicy: trivyTypes.String("TLS_1_0", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "SAM API TLS v1.2",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				APIs: []sam.API{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						DomainConfiguration: sam.DomainConfiguration{
							Metadata:       trivyTypes.NewTestMetadata(),
							SecurityPolicy: trivyTypes.String("TLS_1_2", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0113": {
		{
			name: "API logging not configured",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				APIs: []sam.API{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						AccessLogging: sam.AccessLogging{
							Metadata:              trivyTypes.NewTestMetadata(),
							CloudwatchLogGroupARN: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "API logging configured",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				APIs: []sam.API{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						AccessLogging: sam.AccessLogging{
							Metadata:              trivyTypes.NewTestMetadata(),
							CloudwatchLogGroupARN: trivyTypes.String("log-group-arn", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0110": {
		{
			name: "API unencrypted cache data",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				APIs: []sam.API{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						RESTMethodSettings: sam.RESTMethodSettings{
							Metadata:           trivyTypes.NewTestMetadata(),
							CacheDataEncrypted: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "API encrypted cache data",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				APIs: []sam.API{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						RESTMethodSettings: sam.RESTMethodSettings{
							Metadata:           trivyTypes.NewTestMetadata(),
							CacheDataEncrypted: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0111": {
		{
			name: "API X-Ray tracing disabled",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				APIs: []sam.API{
					{
						Metadata:       trivyTypes.NewTestMetadata(),
						TracingEnabled: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "API X-Ray tracing enabled",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				APIs: []sam.API{
					{
						Metadata:       trivyTypes.NewTestMetadata(),
						TracingEnabled: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0125": {
		{
			name: "SAM pass-through tracing mode",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				Functions: []sam.Function{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Tracing:  trivyTypes.String(sam.TracingModePassThrough, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "SAM active tracing mode",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				Functions: []sam.Function{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Tracing:  trivyTypes.String(sam.TracingModeActive, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0116": {
		{
			name: "HTTP API logging not configured",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				HttpAPIs: []sam.HttpAPI{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						AccessLogging: sam.AccessLogging{
							Metadata:              trivyTypes.NewTestMetadata(),
							CloudwatchLogGroupARN: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "HTTP API logging configured",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				HttpAPIs: []sam.HttpAPI{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						AccessLogging: sam.AccessLogging{
							Metadata:              trivyTypes.NewTestMetadata(),
							CloudwatchLogGroupARN: trivyTypes.String("log-group-arn", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0119": {
		{
			name: "State machine logging disabled",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				StateMachines: []sam.StateMachine{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						LoggingConfiguration: sam.LoggingConfiguration{
							Metadata:       trivyTypes.NewTestMetadata(),
							LoggingEnabled: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "State machine logging enabled",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				StateMachines: []sam.StateMachine{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						LoggingConfiguration: sam.LoggingConfiguration{
							Metadata:       trivyTypes.NewTestMetadata(),
							LoggingEnabled: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0117": {
		{
			name: "State machine tracing disabled",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				StateMachines: []sam.StateMachine{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Tracing: sam.TracingConfiguration{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "State machine tracing enabled",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				StateMachines: []sam.StateMachine{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Tracing: sam.TracingConfiguration{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0121": {
		{
			name: "SAM simple table SSE disabled",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				SimpleTables: []sam.SimpleTable{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						SSESpecification: sam.SSESpecification{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "SAM simple table SSE enabled",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				SimpleTables: []sam.SimpleTable{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						SSESpecification: sam.SSESpecification{
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
