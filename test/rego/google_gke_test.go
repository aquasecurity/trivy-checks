package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/google"
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/gke"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(googleGkeTestCases)
}

var googleGkeTestCases = testCases{
	"AVD-GCP-0063": {
		{
			name: "Node pool auto repair disabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NodePools: []gke.NodePool{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Management: gke.Management{
									Metadata:         trivyTypes.NewTestMetadata(),
									EnableAutoRepair: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Node pool auto repair enabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NodePools: []gke.NodePool{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Management: gke.Management{
									Metadata:         trivyTypes.NewTestMetadata(),
									EnableAutoRepair: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0058": {
		{
			name: "Node pool auto upgrade disabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NodePools: []gke.NodePool{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Management: gke.Management{
									Metadata:          trivyTypes.NewTestMetadata(),
									EnableAutoUpgrade: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Node pool auto upgrade enabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NodePools: []gke.NodePool{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Management: gke.Management{
									Metadata:          trivyTypes.NewTestMetadata(),
									EnableAutoUpgrade: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0049": {
		{
			name: "Cluster IP aliasing disabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						IPAllocationPolicy: gke.IPAllocationPolicy{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster IP aliasing enabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						IPAllocationPolicy: gke.IPAllocationPolicy{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0061": {
		{
			name: "Cluster master authorized networks disabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						MasterAuthorizedNetworks: gke.MasterAuthorizedNetworks{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster master authorized networks enabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						MasterAuthorizedNetworks: gke.MasterAuthorizedNetworks{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0056": {
		{
			name: "Cluster network policy disabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NetworkPolicy: gke.NetworkPolicy{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster network policy enabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NetworkPolicy: gke.NetworkPolicy{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Cluster autopilot enabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NetworkPolicy: gke.NetworkPolicy{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
						EnableAutpilot: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Dataplane v2 enabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NetworkPolicy: gke.NetworkPolicy{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
						DatapathProvider: trivyTypes.String("ADVANCED_DATAPATH", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0059": {
		{
			name: "Cluster private nodes disabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						PrivateCluster: gke.PrivateCluster{
							Metadata:           trivyTypes.NewTestMetadata(),
							EnablePrivateNodes: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster private nodes enabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						PrivateCluster: gke.PrivateCluster{
							Metadata:           trivyTypes.NewTestMetadata(),
							EnablePrivateNodes: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0060": {
		{
			name: "Cluster missing logging service provider",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata:       trivyTypes.NewTestMetadata(),
						LoggingService: trivyTypes.String("", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster with StackDriver logging configured",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata:       trivyTypes.NewTestMetadata(),
						LoggingService: trivyTypes.String("logging.googleapis.com/kubernetes", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0052": {
		{
			name: "Cluster missing monitoring service provider",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata:          trivyTypes.NewTestMetadata(),
						MonitoringService: trivyTypes.String("", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster with StackDriver monitoring configured",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata:          trivyTypes.NewTestMetadata(),
						MonitoringService: trivyTypes.String("monitoring.googleapis.com/kubernetes", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0048": {
		{
			name: "Cluster legacy metadata endpoints enabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:              trivyTypes.NewTestMetadata(),
							EnableLegacyEndpoints: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
						RemoveDefaultNodePool: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster legacy metadata endpoints disabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:              trivyTypes.NewTestMetadata(),
							EnableLegacyEndpoints: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
						RemoveDefaultNodePool: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Cluster legacy metadata endpoints disabled on non-default node pool",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:              trivyTypes.NewTestMetadata(),
							EnableLegacyEndpoints: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
						RemoveDefaultNodePool: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						NodePools: []gke.NodePool{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								NodeConfig: gke.NodeConfig{
									EnableLegacyEndpoints: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Cluster legacy metadata endpoints enabled on non-default node pool",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:              trivyTypes.NewTestMetadata(),
							EnableLegacyEndpoints: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
						RemoveDefaultNodePool: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						NodePools: []gke.NodePool{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								NodeConfig: gke.NodeConfig{
									EnableLegacyEndpoints: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
	},
	"AVD-GCP-0064": {
		{
			name: "Cluster master authentication by certificate",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						MasterAuth: gke.MasterAuth{
							Metadata: trivyTypes.NewTestMetadata(),
							ClientCertificate: gke.ClientCertificate{
								Metadata:         trivyTypes.NewTestMetadata(),
								IssueCertificate: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster master authentication by username/password",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						MasterAuth: gke.MasterAuth{
							Metadata: trivyTypes.NewTestMetadata(),
							ClientCertificate: gke.ClientCertificate{
								Metadata:         trivyTypes.NewTestMetadata(),
								IssueCertificate: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							},
							Username: trivyTypes.String("username", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster master authentication by certificate or username/password disabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						MasterAuth: gke.MasterAuth{
							Metadata: trivyTypes.NewTestMetadata(),
							ClientCertificate: gke.ClientCertificate{
								Metadata:         trivyTypes.NewTestMetadata(),
								IssueCertificate: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							},
							Username: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0053": {
		{
			name: "Master authorized network with public CIDR",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						MasterAuthorizedNetworks: gke.MasterAuthorizedNetworks{
							Metadata: trivyTypes.NewTestMetadata(),
							CIDRs: []trivyTypes.StringValue{
								trivyTypes.String("0.0.0.0/0", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Master authorized network with private CIDR",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						MasterAuthorizedNetworks: gke.MasterAuthorizedNetworks{
							Metadata: trivyTypes.NewTestMetadata(),
							CIDRs: []trivyTypes.StringValue{
								trivyTypes.String("10.10.128.0/24", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0057": {
		{
			name: "Cluster node pools metadata exposed by default",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata: trivyTypes.NewTestMetadata(),
							WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
								Metadata:     trivyTypes.NewTestMetadata(),
								NodeMetadata: trivyTypes.String("UNSPECIFIED", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Node pool metadata exposed",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata: trivyTypes.NewTestMetadata(),
							WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
								Metadata:     trivyTypes.NewTestMetadata(),
								NodeMetadata: trivyTypes.String("SECURE", trivyTypes.NewTestMetadata()),
							},
						},
						NodePools: []gke.NodePool{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								NodeConfig: gke.NodeConfig{
									Metadata: trivyTypes.NewTestMetadata(),
									WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
										Metadata:     trivyTypes.NewTestMetadata(),
										NodeMetadata: trivyTypes.String("EXPOSE", trivyTypes.NewTestMetadata()),
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
			name: "Cluster node pools metadata secured",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata: trivyTypes.NewTestMetadata(),
							WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
								Metadata:     trivyTypes.NewTestMetadata(),
								NodeMetadata: trivyTypes.String("SECURE", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0054": {
		{
			name: "Cluster node config image type set to Ubuntu",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:  trivyTypes.NewTestMetadata(),
							ImageType: trivyTypes.String("UBUNTU", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster node pool image type set to Ubuntu",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:  trivyTypes.NewTestMetadata(),
							ImageType: trivyTypes.String("COS", trivyTypes.NewTestMetadata()),
						},
						NodePools: []gke.NodePool{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								NodeConfig: gke.NodeConfig{
									Metadata:  trivyTypes.NewTestMetadata(),
									ImageType: trivyTypes.String("UBUNTU", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster node config image type set to Container-Optimized OS",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:  trivyTypes.NewTestMetadata(),
							ImageType: trivyTypes.String("COS_CONTAINERD", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0055": {
		{
			name: "Cluster shielded nodes disabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata:            trivyTypes.NewTestMetadata(),
						EnableShieldedNodes: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster shielded nodes enabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata:            trivyTypes.NewTestMetadata(),
						EnableShieldedNodes: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0051": {
		{
			name: "Cluster with no resource labels defined",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata:       trivyTypes.NewTestMetadata(),
						ResourceLabels: trivyTypes.Map(map[string]string{}, trivyTypes.NewTestMetadata().GetMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster with resource labels defined",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						ResourceLabels: trivyTypes.Map(map[string]string{
							"env": "staging",
						}, trivyTypes.NewTestMetadata().GetMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0062": {
		{
			name: "Cluster legacy ABAC enabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata:         trivyTypes.NewTestMetadata(),
						EnableLegacyABAC: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster legacy ABAC disabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata:         trivyTypes.NewTestMetadata(),
						EnableLegacyABAC: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0050": {
		{
			name: "Cluster node config with default service account",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata:              trivyTypes.NewTestMetadata(),
						RemoveDefaultNodePool: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						NodeConfig: gke.NodeConfig{
							Metadata:       trivyTypes.NewTestMetadata(),
							ServiceAccount: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster node config with service account provided",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata:              trivyTypes.NewTestMetadata(),
						RemoveDefaultNodePool: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						NodeConfig: gke.NodeConfig{
							Metadata:       trivyTypes.NewTestMetadata(),
							ServiceAccount: trivyTypes.String("service-account", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
