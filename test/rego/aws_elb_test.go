package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws"
	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/elb"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(awsElbTestCases)
}

var awsElbTestCases = testCases{
	"AVD-AWS-0053": {
		{
			name: "Load balancer publicly accessible",
			input: state.State{AWS: aws.AWS{ELB: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Type:     trivyTypes.String(elb.TypeApplication, trivyTypes.NewTestMetadata()),
						Internal: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Load balancer internally accessible",
			input: state.State{AWS: aws.AWS{ELB: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Type:     trivyTypes.String(elb.TypeApplication, trivyTypes.NewTestMetadata()),
						Internal: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0052": {
		{
			name: "Load balancer drop invalid headers disabled",
			input: state.State{AWS: aws.AWS{ELB: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata:                trivyTypes.NewTestMetadata(),
						Type:                    trivyTypes.String(elb.TypeApplication, trivyTypes.NewTestMetadata()),
						DropInvalidHeaderFields: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Load balancer drop invalid headers enabled",
			input: state.State{AWS: aws.AWS{ELB: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata:                trivyTypes.NewTestMetadata(),
						Type:                    trivyTypes.String(elb.TypeApplication, trivyTypes.NewTestMetadata()),
						DropInvalidHeaderFields: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Classic load balanace doesn't fail when no drop headers",
			input: state.State{AWS: aws.AWS{ELB: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Type:     trivyTypes.String(elb.TypeClassic, trivyTypes.NewTestMetadata()),
					},
				}}},
			},
			expected: false,
		},
	},
	"AVD-AWS-0054": {
		{
			name: "Load balancer listener with HTTP protocol",
			input: state.State{AWS: aws.AWS{ELB: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Type:     trivyTypes.String(elb.TypeApplication, trivyTypes.NewTestMetadata()),
						Listeners: []elb.Listener{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Protocol: trivyTypes.String("HTTP", trivyTypes.NewTestMetadata()),
								DefaultActions: []elb.Action{
									{
										Metadata: trivyTypes.NewTestMetadata(),
										Type:     trivyTypes.String("forward", trivyTypes.NewTestMetadata()),
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
			name: "Load balancer listener with HTTP protocol but redirect default action",
			input: state.State{AWS: aws.AWS{ELB: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Type:     trivyTypes.String(elb.TypeApplication, trivyTypes.NewTestMetadata()),
						Listeners: []elb.Listener{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Protocol: trivyTypes.String("HTTP", trivyTypes.NewTestMetadata()),
								DefaultActions: []elb.Action{
									{
										Metadata: trivyTypes.NewTestMetadata(),
										Type:     trivyTypes.String("redirect", trivyTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Load balancer listener with HTTP protocol but redirect among multiple default actions",
			input: state.State{AWS: aws.AWS{ELB: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Type:     trivyTypes.String(elb.TypeApplication, trivyTypes.NewTestMetadata()),
						Listeners: []elb.Listener{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Protocol: trivyTypes.String("HTTP", trivyTypes.NewTestMetadata()),
								DefaultActions: []elb.Action{
									{
										Metadata: trivyTypes.NewTestMetadata(),
										Type:     trivyTypes.String("forward", trivyTypes.NewTestMetadata()),
									},
									{
										Metadata: trivyTypes.NewTestMetadata(),
										Type:     trivyTypes.String("redirect", trivyTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Load balancer listener with HTTPS protocol",
			input: state.State{AWS: aws.AWS{ELB: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Type:     trivyTypes.String(elb.TypeApplication, trivyTypes.NewTestMetadata()),
						Listeners: []elb.Listener{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Protocol: trivyTypes.String("HTTPS", trivyTypes.NewTestMetadata()),
								DefaultActions: []elb.Action{
									{
										Metadata: trivyTypes.NewTestMetadata(),
										Type:     trivyTypes.String("forward", trivyTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0047": {
		{
			name: "Load balancer listener using TLS v1.0",
			input: state.State{AWS: aws.AWS{ELB: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Listeners: []elb.Listener{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								TLSPolicy: trivyTypes.String("ELBSecurityPolicy-TLS-1-0-2015-04", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Load balancer listener using TLS v1.2",
			input: state.State{AWS: aws.AWS{ELB: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Listeners: []elb.Listener{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								TLSPolicy: trivyTypes.String("ELBSecurityPolicy-TLS-1-2-2017-01", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Load balancer listener using TLS v1.3",
			input: state.State{AWS: aws.AWS{ELB: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Listeners: []elb.Listener{
							{
								Metadata:  trivyTypes.NewTestMetadata(),
								TLSPolicy: trivyTypes.String("ELBSecurityPolicy-TLS13-1-2-2021-06", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
