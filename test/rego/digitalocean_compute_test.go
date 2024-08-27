package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/digitalocean"
	"github.com/aquasecurity/trivy/pkg/iac/providers/digitalocean/compute"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(digitalOceanTestCases)
}

var digitalOceanTestCases = testCases{
	"AVD-DIG-0008": {
		{
			name: "Kubernetes cluster auto-upgrade disabled",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Compute: compute.Compute{
				KubernetesClusters: []compute.KubernetesCluster{
					{
						Metadata:    trivyTypes.NewTestMetadata(),
						AutoUpgrade: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Kubernetes cluster auto-upgrade enabled",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Compute: compute.Compute{
				KubernetesClusters: []compute.KubernetesCluster{
					{
						Metadata:    trivyTypes.NewTestMetadata(),
						AutoUpgrade: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-DIG-0002": {
		{
			name: "Load balancer forwarding rule using HTTP",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Compute: compute.Compute{
				LoadBalancers: []compute.LoadBalancer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ForwardingRules: []compute.ForwardingRule{
							{
								Metadata:      trivyTypes.NewTestMetadata(),
								EntryProtocol: trivyTypes.String("http", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Load balancer forwarding rule using HTTPS",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Compute: compute.Compute{
				LoadBalancers: []compute.LoadBalancer{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ForwardingRules: []compute.ForwardingRule{
							{
								Metadata:      trivyTypes.NewTestMetadata(),
								EntryProtocol: trivyTypes.String("https", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Load balancer forwarding rule using HTTP, but HTTP redirection to HTTPS is enabled",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Compute: compute.Compute{
				LoadBalancers: []compute.LoadBalancer{
					{
						Metadata:            trivyTypes.NewTestMetadata(),
						RedirectHttpToHttps: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						ForwardingRules: []compute.ForwardingRule{
							{
								Metadata:      trivyTypes.NewTestMetadata(),
								EntryProtocol: trivyTypes.String("http", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-DIG-0005": {
		{
			name: "Kubernetes cluster surge upgrade disabled",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Compute: compute.Compute{
				KubernetesClusters: []compute.KubernetesCluster{
					{
						Metadata:     trivyTypes.NewTestMetadata(),
						SurgeUpgrade: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Kubernetes cluster surge upgrade enabled",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Compute: compute.Compute{
				KubernetesClusters: []compute.KubernetesCluster{
					{
						Metadata:     trivyTypes.NewTestMetadata(),
						SurgeUpgrade: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-DIG-0003": {
		{
			name: "Firewall outbound rule with multiple public destination addresses",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Compute: compute.Compute{
				Firewalls: []compute.Firewall{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						OutboundRules: []compute.OutboundFirewallRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								DestinationAddresses: []trivyTypes.StringValue{
									trivyTypes.String("0.0.0.0/0", trivyTypes.NewTestMetadata()),
									trivyTypes.String("::/0", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Firewall outbound rule with a private destination address",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Compute: compute.Compute{
				Firewalls: []compute.Firewall{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						OutboundRules: []compute.OutboundFirewallRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								DestinationAddresses: []trivyTypes.StringValue{
									trivyTypes.String("192.168.1.0/24", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-DIG-0001": {
		{
			name: "Firewall inbound rule with multiple public source addresses",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Compute: compute.Compute{
				Firewalls: []compute.Firewall{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						InboundRules: []compute.InboundFirewallRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								SourceAddresses: []trivyTypes.StringValue{
									trivyTypes.String("0.0.0.0/0", trivyTypes.NewTestMetadata()),
									trivyTypes.String("::/0", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Firewall inbound rule with a private source address",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Compute: compute.Compute{
				Firewalls: []compute.Firewall{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						InboundRules: []compute.InboundFirewallRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								SourceAddresses: []trivyTypes.StringValue{
									trivyTypes.String("192.168.1.0/24", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-DIG-0004": {
		{
			name: "Droplet missing SSH keys",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Compute: compute.Compute{
				Droplets: []compute.Droplet{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						SSHKeys:  []trivyTypes.StringValue{},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Droplet with an SSH key provided",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Compute: compute.Compute{
				Droplets: []compute.Droplet{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						SSHKeys: []trivyTypes.StringValue{
							trivyTypes.String("my-ssh-key", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
