package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/compute"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

var azureComputeTestCases = testCases{
	"AVD-AZU-0039": {
		{
			name: "Linux VM password authentication enabled",
			input: state.State{Azure: azure.Azure{Compute: compute.Compute{
				LinuxVirtualMachines: []compute.LinuxVirtualMachine{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						OSProfileLinuxConfig: compute.OSProfileLinuxConfig{
							Metadata:                      trivyTypes.NewTestMetadata(),
							DisablePasswordAuthentication: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Linux VM password authentication disabled",
			input: state.State{Azure: azure.Azure{Compute: compute.Compute{
				LinuxVirtualMachines: []compute.LinuxVirtualMachine{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						OSProfileLinuxConfig: compute.OSProfileLinuxConfig{
							Metadata:                      trivyTypes.NewTestMetadata(),
							DisablePasswordAuthentication: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0038": {
		{
			name: "Managed disk encryption disabled",
			input: state.State{Azure: azure.Azure{Compute: compute.Compute{
				ManagedDisks: []compute.ManagedDisk{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: compute.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Managed disk encryption enabled",
			input: state.State{Azure: azure.Azure{Compute: compute.Compute{
				ManagedDisks: []compute.ManagedDisk{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Encryption: compute.Encryption{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0037": {
		{
			name: "Secrets in custom data",
			input: state.State{Azure: azure.Azure{Compute: compute.Compute{
				LinuxVirtualMachines: []compute.LinuxVirtualMachine{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						VirtualMachine: compute.VirtualMachine{
							Metadata:   trivyTypes.NewTestMetadata(),
							CustomData: trivyTypes.String(`export DATABASE_PASSWORD=\"SomeSortOfPassword\"`, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "No secrets in custom data",
			input: state.State{Azure: azure.Azure{Compute: compute.Compute{
				LinuxVirtualMachines: []compute.LinuxVirtualMachine{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						VirtualMachine: compute.VirtualMachine{
							Metadata:   trivyTypes.NewTestMetadata(),
							CustomData: trivyTypes.String(`export GREETING="Hello there"`, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
