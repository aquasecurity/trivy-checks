package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/storage"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(azureStorageTestCases)
}

var azureStorageTestCases = testCases{
	"AVD-AZU-0010": {
		{
			name: "Azure storage rule doesn't allow bypass access",
			input: state.State{Azure: azure.Azure{Storage: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NetworkRules: []storage.NetworkRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Bypass:   []trivyTypes.StringValue{},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Azure storage rule allows bypass access to Microsoft services",
			input: state.State{Azure: azure.Azure{Storage: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NetworkRules: []storage.NetworkRule{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Bypass: []trivyTypes.StringValue{
									trivyTypes.String("AzureServices", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0012": {
		{
			name: "Storage network rule allows access by default",
			input: state.State{Azure: azure.Azure{Storage: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NetworkRules: []storage.NetworkRule{
							{
								Metadata:       trivyTypes.NewTestMetadata(),
								AllowByDefault: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Storage network rule denies access by default",
			input: state.State{Azure: azure.Azure{Storage: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						NetworkRules: []storage.NetworkRule{
							{
								Metadata:       trivyTypes.NewTestMetadata(),
								AllowByDefault: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0008": {
		{
			name: "Storage account HTTPS enforcement disabled",
			input: state.State{Azure: azure.Azure{Storage: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata:     trivyTypes.NewTestMetadata(),
						EnforceHTTPS: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Storage account HTTPS enforcement enabled",
			input: state.State{Azure: azure.Azure{Storage: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata:     trivyTypes.NewTestMetadata(),
						EnforceHTTPS: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0007": {
		{
			name: "Storage account container public access set to blob",
			input: state.State{Azure: azure.Azure{Storage: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Containers: []storage.Container{
							{
								Metadata:     trivyTypes.NewTestMetadata(),
								PublicAccess: trivyTypes.String(storage.PublicAccessBlob, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Storage account container public access set to container",
			input: state.State{Azure: azure.Azure{Storage: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Containers: []storage.Container{
							{
								Metadata:     trivyTypes.NewTestMetadata(),
								PublicAccess: trivyTypes.String(storage.PublicAccessContainer, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Storage account container public access set to off",
			input: state.State{Azure: azure.Azure{Storage: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Containers: []storage.Container{
							{
								Metadata:     trivyTypes.NewTestMetadata(),
								PublicAccess: trivyTypes.String(storage.PublicAccessOff, trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0009": {
		{
			name: "Storage account queue properties logging disabled",
			input: state.State{Azure: azure.Azure{Storage: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						QueueProperties: storage.QueueProperties{
							Metadata:      trivyTypes.NewTestMetadata(),
							EnableLogging: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
						Queues: []storage.Queue{
							{
								Metadata: trivyTypes.NewTestMetadata(),
								Name:     trivyTypes.String("my-queue", trivyTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Storage account queue properties logging disabled with no queues",
			input: state.State{Azure: azure.Azure{Storage: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						QueueProperties: storage.QueueProperties{
							Metadata:      trivyTypes.NewTestMetadata(),
							EnableLogging: trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Storage account queue properties logging enabled",
			input: state.State{Azure: azure.Azure{Storage: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						QueueProperties: storage.QueueProperties{
							Metadata:      trivyTypes.NewTestMetadata(),
							EnableLogging: trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0011": {
		{
			name: "Storage account minimum TLS version unspecified",
			input: state.State{Azure: azure.Azure{Storage: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: trivyTypes.NewTestMetadata(),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Storage account minimum TLS version 1.0",
			input: state.State{Azure: azure.Azure{Storage: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata:          trivyTypes.NewTestMetadata(),
						MinimumTLSVersion: trivyTypes.String("TLS1_0", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Storage account minimum TLS version 1.2",
			input: state.State{Azure: azure.Azure{Storage: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata:          trivyTypes.NewTestMetadata(),
						MinimumTLSVersion: trivyTypes.String("TLS1_2", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
