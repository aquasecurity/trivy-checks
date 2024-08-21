package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/container"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

var azureContainerTestCases = testCases{
	"AVD-AZU-0043": {
		{
			name: "Cluster missing network policy configuration",
			input: state.State{Azure: azure.Azure{Container: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NetworkProfile: container.NetworkProfile{
							Metadata:      trivyTypes.NewTestMetadata(),
							NetworkPolicy: trivyTypes.String("", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster with network policy configured",
			input: state.State{Azure: azure.Azure{Container: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NetworkProfile: container.NetworkProfile{
							Metadata:      trivyTypes.NewTestMetadata(),
							NetworkPolicy: trivyTypes.String("calico", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0041": {
		{
			name: "API server authorized IP ranges undefined",
			input: state.State{Azure: azure.Azure{Container: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata:                    trivyTypes.NewTestMetadata(),
						EnablePrivateCluster:        trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						APIServerAuthorizedIPRanges: []trivyTypes.StringValue{},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "API server authorized IP ranges defined",
			input: state.State{Azure: azure.Azure{Container: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata:             trivyTypes.NewTestMetadata(),
						EnablePrivateCluster: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						APIServerAuthorizedIPRanges: []trivyTypes.StringValue{
							trivyTypes.String("1.2.3.4/32", trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0040": {
		{
			name: "Logging via OMS agent disabled",
			input: state.State{Azure: azure.Azure{Container: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						AddonProfile: container.AddonProfile{
							Metadata: trivyTypes.NewTestMetadata(),
							OMSAgent: container.OMSAgent{
								Metadata: trivyTypes.NewTestMetadata(),
								Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Logging via OMS agent enabled",
			input: state.State{Azure: azure.Azure{Container: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						AddonProfile: container.AddonProfile{
							Metadata: trivyTypes.NewTestMetadata(),
							OMSAgent: container.OMSAgent{
								Metadata: trivyTypes.NewTestMetadata(),
								Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0042": {
		{
			name: "Role based access control disabled",
			input: state.State{Azure: azure.Azure{Container: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						RoleBasedAccessControl: container.RoleBasedAccessControl{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Role based access control enabled",
			input: state.State{Azure: azure.Azure{Container: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						RoleBasedAccessControl: container.RoleBasedAccessControl{
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
