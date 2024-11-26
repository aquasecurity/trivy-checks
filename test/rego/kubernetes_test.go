package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/kubernetes"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(kubernetesTestCases)
}

var kubernetesTestCases = testCases{
	"AVD-KUBE-0001": []testCase{
		{
			name: "Public source CIDR",
			input: state.State{Kubernetes: kubernetes.Kubernetes{
				NetworkPolicies: []kubernetes.NetworkPolicy{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Spec: kubernetes.NetworkPolicySpec{
							Metadata: trivyTypes.NewTestMetadata(),
							Ingress: kubernetes.Ingress{
								Metadata: trivyTypes.NewTestMetadata(),
								SourceCIDRs: []trivyTypes.StringValue{
									trivyTypes.String("0.0.0.0/0", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: true,
		},
		{
			name: "Private source CIDR",
			input: state.State{Kubernetes: kubernetes.Kubernetes{
				NetworkPolicies: []kubernetes.NetworkPolicy{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Spec: kubernetes.NetworkPolicySpec{
							Metadata: trivyTypes.NewTestMetadata(),
							Ingress: kubernetes.Ingress{
								Metadata: trivyTypes.NewTestMetadata(),
								SourceCIDRs: []trivyTypes.StringValue{
									trivyTypes.String("10.0.0.0/16", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
	},
	"AVD-KUBE-0002": []testCase{
		{
			name: "Public destination CIDR",
			input: state.State{Kubernetes: kubernetes.Kubernetes{
				NetworkPolicies: []kubernetes.NetworkPolicy{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Spec: kubernetes.NetworkPolicySpec{
							Metadata: trivyTypes.NewTestMetadata(),
							Egress: kubernetes.Egress{
								Metadata: trivyTypes.NewTestMetadata(),
								DestinationCIDRs: []trivyTypes.StringValue{
									trivyTypes.String("0.0.0.0/0", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: true,
		},
		{
			name: "Private destination CIDR",
			input: state.State{Kubernetes: kubernetes.Kubernetes{
				NetworkPolicies: []kubernetes.NetworkPolicy{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Spec: kubernetes.NetworkPolicySpec{
							Metadata: trivyTypes.NewTestMetadata(),
							Egress: kubernetes.Egress{
								Metadata: trivyTypes.NewTestMetadata(),
								DestinationCIDRs: []trivyTypes.StringValue{
									trivyTypes.String("10.0.0.0/16", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
	},
}
