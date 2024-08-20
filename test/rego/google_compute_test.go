package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/google"
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/compute"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

var googleComputeTestCases = testCases{
	"AVD-GCP-0034": {
		{
			name: "Disk missing KMS key link",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Disks: []compute.Disk{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: compute.DiskEncryption{
							Metadata:   trivyTypes.NewTestMetadata(),
							KMSKeyLink: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Disk with KMS key link provided",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Disks: []compute.Disk{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: compute.DiskEncryption{
							Metadata:   trivyTypes.NewTestMetadata(),
							KMSKeyLink: trivyTypes.String("kms-key-link", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0037": {
		{
			name: "Disk with plaintext encryption key",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Disks: []compute.Disk{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: compute.DiskEncryption{
							Metadata: trivyTypes.NewTestMetadata(),
							RawKey:   trivyTypes.Bytes([]byte("b2ggbm8gdGhpcyBpcyBiYWQ"), trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance disk with plaintext encryption key",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						BootDisks: []compute.Disk{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Encryption: compute.DiskEncryption{
									Metadata: trivyTypes.NewTestMetadata(),
									RawKey:   trivyTypes.Bytes([]byte("b2ggbm8gdGhpcyBpcyBiYWQ"), trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Disks with no plaintext encryption keys",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Disks: []compute.Disk{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: compute.DiskEncryption{
							Metadata: trivyTypes.NewTestMetadata(),
							RawKey:   trivyTypes.Bytes([]byte(""), trivyTypes.NewTestMetadata()),
						},
					},
				},
				Instances: []compute.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						BootDisks: []compute.Disk{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Encryption: compute.DiskEncryption{
									Metadata: trivyTypes.NewTestMetadata(),
									RawKey:   trivyTypes.Bytes([]byte(""), trivyTypes.NewTestMetadata()),
								},
							},
						},
						AttachedDisks: []compute.Disk{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Encryption: compute.DiskEncryption{
									Metadata: trivyTypes.NewTestMetadata(),
									RawKey:   trivyTypes.Bytes([]byte(""), trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0045": {
		{
			name: "Instance shielded VM integrity monitoring disabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ShieldedVM: compute.ShieldedVMConfig{
							Metadata:                   trivyTypes.NewTestMetadata(),
							IntegrityMonitoringEnabled: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance shielded VM integrity monitoring enabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ShieldedVM: compute.ShieldedVMConfig{
							Metadata:                   trivyTypes.NewTestMetadata(),
							IntegrityMonitoringEnabled: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0067": {
		{
			name: "Instance shielded VM secure boot disabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ShieldedVM: compute.ShieldedVMConfig{
							Metadata:          trivyTypes.NewTestMetadata(),
							SecureBootEnabled: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance shielded VM secure boot enabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ShieldedVM: compute.ShieldedVMConfig{
							Metadata:          trivyTypes.NewTestMetadata(),
							SecureBootEnabled: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0041": {
		{
			name: "Instance shielded VM VTPM disabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ShieldedVM: compute.ShieldedVMConfig{
							Metadata:    trivyTypes.NewTestMetadata(),
							VTPMEnabled: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance shielded VM VTPM enabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ShieldedVM: compute.ShieldedVMConfig{
							Metadata:    trivyTypes.NewTestMetadata(),
							VTPMEnabled: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0029": {
		{
			name: "Subnetwork VPC flow logs disabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Networks: []compute.Network{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Subnetworks: []compute.SubNetwork{
							{
								Metadata:       trivyTypes.NewTestMetadata(),
								EnableFlowLogs: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Subnetwork VPC flow logs enabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Networks: []compute.Network{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Subnetworks: []compute.SubNetwork{
							{
								Metadata:       trivyTypes.NewTestMetadata(),
								EnableFlowLogs: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Proxy-only subnets and logs disabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Networks: []compute.Network{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Subnetworks: []compute.SubNetwork{
							{
								Metadata:       trivyTypes.NewTestMetadata(),
								EnableFlowLogs: trivyTypes.BoolDefault(false, trivyTypes.NewTestMetadata()),
								Purpose:        trivyTypes.String("REGIONAL_MANAGED_PROXY", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0044": {
		{
			name: "Instance service account not specified",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ServiceAccount: compute.ServiceAccount{
							Metadata:  trivyTypes.NewTestMetadata(),
							Email:     trivyTypes.String("", trivyTypes.NewTestMetadata()),
							IsDefault: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance service account using the default email",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ServiceAccount: compute.ServiceAccount{
							Metadata:  trivyTypes.NewTestMetadata(),
							Email:     trivyTypes.String("1234567890-compute@developer.gserviceaccount.com", trivyTypes.NewTestMetadata()),
							IsDefault: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance service account with email provided",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ServiceAccount: compute.ServiceAccount{
							Metadata:  trivyTypes.NewTestMetadata(),
							Email:     trivyTypes.String("proper@email.com", trivyTypes.NewTestMetadata()),
							IsDefault: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0043": {
		{
			name: "Instance IP forwarding enabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata:     trivyTypes.NewTestMetadata(),
						CanIPForward: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance IP forwarding disabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata:     trivyTypes.NewTestMetadata(),
						CanIPForward: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0036": {
		{
			name: "Instance OS login disabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata:       trivyTypes.NewTestMetadata(),
						OSLoginEnabled: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance OS login enabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata:       trivyTypes.NewTestMetadata(),
						OSLoginEnabled: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0030": {
		{
			name: "Instance project level SSH keys blocked",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata:                    trivyTypes.NewTestMetadata(),
						EnableProjectSSHKeyBlocking: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance project level SSH keys allowed",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata:                    trivyTypes.NewTestMetadata(),
						EnableProjectSSHKeyBlocking: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0035": {
		{
			name: "Firewall egress rule with multiple public destination addresses",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Networks: []compute.Network{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Firewall: &compute.Firewall{
							Metadata: trivyTypes.NewTestMetadata(),
							EgressRules: []compute.EgressRule{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									FirewallRule: compute.FirewallRule{
										Metadata: trivyTypes.NewTestMetadata(),
										IsAllow:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
										Enforced: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
									},
									DestinationRanges: []trivyTypes.StringValue{
										trivyTypes.String("0.0.0.0/0", trivyTypes.NewTestMetadata()),
										trivyTypes.String("1.2.3.4/32", trivyTypes.NewTestMetadata()),
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
			name: "Firewall egress rule with public destination address",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Networks: []compute.Network{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Firewall: &compute.Firewall{
							Metadata: trivyTypes.NewTestMetadata(),
							EgressRules: []compute.EgressRule{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									FirewallRule: compute.FirewallRule{
										Metadata: trivyTypes.NewTestMetadata(),
										IsAllow:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
										Enforced: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
									},
									DestinationRanges: []trivyTypes.StringValue{
										trivyTypes.String("1.2.3.4/32", trivyTypes.NewTestMetadata()),
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
	"AVD-GCP-0027": {
		{
			name: "Firewall ingress rule with multiple public source addresses",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Networks: []compute.Network{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Firewall: &compute.Firewall{
							Metadata: trivyTypes.NewTestMetadata(),
							IngressRules: []compute.IngressRule{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									FirewallRule: compute.FirewallRule{
										Metadata: trivyTypes.NewTestMetadata(),
										IsAllow:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
										Enforced: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
									},
									SourceRanges: []trivyTypes.StringValue{
										trivyTypes.String("0.0.0.0/0", trivyTypes.NewTestMetadata()),
										trivyTypes.String("1.2.3.4/32", trivyTypes.NewTestMetadata()),
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
			name: "Firewall ingress rule with public source address",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Networks: []compute.Network{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Firewall: &compute.Firewall{
							Metadata: trivyTypes.NewTestMetadata(),
							IngressRules: []compute.IngressRule{
								{
									Metadata: trivyTypes.NewTestMetadata(),
									FirewallRule: compute.FirewallRule{
										Metadata: trivyTypes.NewTestMetadata(),
										IsAllow:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
										Enforced: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
									},
									SourceRanges: []trivyTypes.StringValue{
										trivyTypes.String("1.2.3.4/32", trivyTypes.NewTestMetadata()),
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
	"AVD-GCP-0031": {
		{
			name: "Network interface with public IP",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NetworkInterfaces: []compute.NetworkInterface{
							{
								Metadata:    trivyTypes.NewTestMetadata(),
								HasPublicIP: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Network interface without public IP",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NetworkInterfaces: []compute.NetworkInterface{
							{
								Metadata:    trivyTypes.NewTestMetadata(),
								HasPublicIP: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0032": {
		{
			name: "Instance serial port enabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata:         trivyTypes.NewTestMetadata(),
						EnableSerialPort: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance serial port disabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata:         trivyTypes.NewTestMetadata(),
						EnableSerialPort: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0042": {
		{
			name: "Compute OS login disabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				ProjectMetadata: compute.ProjectMetadata{
					Metadata:      trivyTypes.NewTestMetadata(),
					EnableOSLogin: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
				},
			}}},
			expected: true,
		},
		{
			name: "Compute OS login enabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				ProjectMetadata: compute.ProjectMetadata{
					Metadata:      trivyTypes.NewTestMetadata(),
					EnableOSLogin: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0039": {
		{
			name: "SSL policy minimum TLS version 1.0",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				SSLPolicies: []compute.SSLPolicy{
					{
						Metadata:          trivyTypes.NewTestMetadata(),
						MinimumTLSVersion: trivyTypes.String("TLS_1_0", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "SSL policy minimum TLS version 1.2",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				SSLPolicies: []compute.SSLPolicy{
					{
						Metadata:          trivyTypes.NewTestMetadata(),
						MinimumTLSVersion: trivyTypes.String("TLS_1_2", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0033": {
		{
			name: "Instance disk missing encryption key link",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						BootDisks: []compute.Disk{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Encryption: compute.DiskEncryption{
									Metadata:   trivyTypes.NewTestMetadata(),
									KMSKeyLink: trivyTypes.String("", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance disk encryption key link provided",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						AttachedDisks: []compute.Disk{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Encryption: compute.DiskEncryption{
									Metadata:   trivyTypes.NewTestMetadata(),
									KMSKeyLink: trivyTypes.String("kms-key-link", trivyTypes.NewTestMetadata()),
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
