package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/apigateway"
	v1 "github.com/aquasecurity/trivy/pkg/iac/providers/aws/apigateway/v1"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(awsApigatewayTestCases)
}

var awsApigatewayTestCases = testCases{
	"AVD-AWS-0001": {
		{
			name: "API Gateway stage with no log group ARN",
			input: state.State{AWS: aws.AWS{APIGateway: apigateway.APIGateway{V1: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Stages: []v1.Stage{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								AccessLogging: v1.AccessLogging{
									Metadata:              trivyTypes.NewTestMetadata(),
									CloudwatchLogGroupARN: trivyTypes.String("", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}}},
			expected: true,
		},
		{
			name: "API Gateway stage with log group ARN",
			input: state.State{AWS: aws.AWS{APIGateway: apigateway.APIGateway{V1: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Stages: []v1.Stage{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								AccessLogging: v1.AccessLogging{
									Metadata:              trivyTypes.NewTestMetadata(),
									CloudwatchLogGroupARN: trivyTypes.String("log-group-arn", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}}},
			expected: false,
		},
	},
	"AVD-AWS-0002": {
		{
			name: "API Gateway stage with unencrypted cache",
			input: state.State{AWS: aws.AWS{APIGateway: apigateway.APIGateway{V1: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Stages: []v1.Stage{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								RESTMethodSettings: []v1.RESTMethodSettings{
									{
										Metadata:           trivyTypes.NewTestMetadata(),
										CacheDataEncrypted: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
										CacheEnabled:       trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			}}}},
			expected: true,
		},
		{
			name: "API Gateway stage with encrypted cache",
			input: state.State{AWS: aws.AWS{APIGateway: apigateway.APIGateway{V1: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Stages: []v1.Stage{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								RESTMethodSettings: []v1.RESTMethodSettings{
									{
										Metadata:           trivyTypes.NewTestMetadata(),
										CacheDataEncrypted: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
										CacheEnabled:       trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			}}}},
			expected: false,
		},
		{
			name: "API Gateway stage with caching disabled",
			input: state.State{AWS: aws.AWS{APIGateway: apigateway.APIGateway{V1: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Stages: []v1.Stage{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								RESTMethodSettings: []v1.RESTMethodSettings{
									{
										Metadata:           trivyTypes.NewTestMetadata(),
										CacheDataEncrypted: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
										CacheEnabled:       trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			}}}},
			expected: false,
		},
	},
	"AVD-AWS-0003": {
		{
			name: "API Gateway stage with X-Ray tracing disabled",
			input: state.State{AWS: aws.AWS{APIGateway: apigateway.APIGateway{V1: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Stages: []v1.Stage{
							{
								Metadata:           trivyTypes.NewTestMetadata(),
								XRayTracingEnabled: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}}},
			expected: true,
		},
		{
			name: "API Gateway stage with X-Ray tracing enabled",
			input: state.State{AWS: aws.AWS{APIGateway: apigateway.APIGateway{V1: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Stages: []v1.Stage{
							{
								Metadata:           trivyTypes.NewTestMetadata(),
								XRayTracingEnabled: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}}},
			expected: false,
		},
	},
	"AVD-AWS-0004": {
		{
			name: "API GET method without authorization",
			input: state.State{AWS: aws.AWS{APIGateway: apigateway.APIGateway{V1: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Resources: []v1.Resource{
							{
								Methods: []v1.Method{
									{
										Metadata:          trivyTypes.NewTestMetadata(),
										HTTPMethod:        trivyTypes.String("GET", trivyTypes.NewTestMetadata()),
										APIKeyRequired:    trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
										AuthorizationType: trivyTypes.String(v1.AuthorizationNone, trivyTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			}}}},
			expected: true,
		},
		{
			name: "API OPTION method without authorization",
			input: state.State{AWS: aws.AWS{APIGateway: apigateway.APIGateway{V1: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Resources: []v1.Resource{
							{
								Methods: []v1.Method{
									{
										Metadata:          trivyTypes.NewTestMetadata(),
										HTTPMethod:        trivyTypes.String("OPTION", trivyTypes.NewTestMetadata()),
										APIKeyRequired:    trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
										AuthorizationType: trivyTypes.String(v1.AuthorizationNone, trivyTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			}}}},
			expected: false,
		},
		{
			name: "API GET method with IAM authorization",
			input: state.State{AWS: aws.AWS{APIGateway: apigateway.APIGateway{V1: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Resources: []v1.Resource{
							{
								Methods: []v1.Method{
									{
										Metadata:          trivyTypes.NewTestMetadata(),
										HTTPMethod:        trivyTypes.String("GET", trivyTypes.NewTestMetadata()),
										APIKeyRequired:    trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
										AuthorizationType: trivyTypes.String(v1.AuthorizationIAM, trivyTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			}}}},
			expected: false,
		},
	},
	"AVD-AWS-0005": {
		{
			name: "API Gateway domain name with TLS version 1.0",
			input: state.State{AWS: aws.AWS{APIGateway: apigateway.APIGateway{V1: v1.APIGateway{
				DomainNames: []v1.DomainName{
					{
						Metadata:       trivyTypes.NewTestMetadata(),
						SecurityPolicy: trivyTypes.String("TLS_1_0", trivyTypes.NewTestMetadata()),
					},
				},
			}}}},
			expected: true,
		},
		{
			name: "API Gateway domain name with TLS version 1.2",
			input: state.State{AWS: aws.AWS{APIGateway: apigateway.APIGateway{V1: v1.APIGateway{
				DomainNames: []v1.DomainName{
					{
						Metadata:       trivyTypes.NewTestMetadata(),
						SecurityPolicy: trivyTypes.String("TLS_1_2", trivyTypes.NewTestMetadata()),
					},
				},
			}}}},
			expected: false,
		},
	},
	"AVD-AWS-0190": {
		{
			name: "API Gateway stage with caching disabled",
			input: state.State{AWS: aws.AWS{APIGateway: apigateway.APIGateway{V1: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Stages: []v1.Stage{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								RESTMethodSettings: []v1.RESTMethodSettings{
									{
										Metadata:     trivyTypes.NewTestMetadata(),
										CacheEnabled: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			}}}},
			expected: true,
		},

		{
			name: "API Gateway stage with caching enabled",
			input: state.State{AWS: aws.AWS{APIGateway: apigateway.APIGateway{V1: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Stages: []v1.Stage{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								RESTMethodSettings: []v1.RESTMethodSettings{
									{
										Metadata:     trivyTypes.NewTestMetadata(),
										CacheEnabled: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			}}}},
			expected: false,
		},
	},
}
