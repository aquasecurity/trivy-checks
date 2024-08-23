package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/google"
	"github.com/aquasecurity/trivy/pkg/iac/providers/google/dns"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(googleDnsTestCases)
}

var googleDnsTestCases = testCases{
	"AVD-GCP-0013": {
		{
			name: "DNSSec disabled and required when visibility explicitly public",
			input: state.State{Google: google.Google{DNS: dns.DNS{
				ManagedZones: []dns.ManagedZone{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Visibility: trivyTypes.String("public", trivyTypes.NewTestMetadata()),
						DNSSec: dns.DNSSec{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(false, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "DNSSec enabled",
			input: state.State{Google: google.Google{DNS: dns.DNS{
				ManagedZones: []dns.ManagedZone{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Visibility: trivyTypes.String("public", trivyTypes.NewTestMetadata()),
						DNSSec: dns.DNSSec{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "DNSSec not required when private",
			input: state.State{Google: google.Google{DNS: dns.DNS{
				ManagedZones: []dns.ManagedZone{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Visibility: trivyTypes.String("private", trivyTypes.NewTestMetadata()),
						DNSSec: dns.DNSSec{
							Metadata: trivyTypes.NewTestMetadata(),
							Enabled:  trivyTypes.Bool(true, trivyTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0012": {
		{
			name: "Zone signing using RSA SHA1 key",
			input: state.State{Google: google.Google{DNS: dns.DNS{
				ManagedZones: []dns.ManagedZone{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						DNSSec: dns.DNSSec{
							Metadata: trivyTypes.NewTestMetadata(),
							DefaultKeySpecs: []dns.KeySpecs{
								{
									Metadata:  trivyTypes.NewTestMetadata(),
									Algorithm: trivyTypes.String("rsasha1", trivyTypes.NewTestMetadata()),
									KeyType:   trivyTypes.String("keySigning", trivyTypes.NewTestMetadata()),
								},
								{
									Metadata:  trivyTypes.NewTestMetadata(),
									Algorithm: trivyTypes.String("rsasha1", trivyTypes.NewTestMetadata()),
									KeyType:   trivyTypes.String("zoneSigning", trivyTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Zone signing using RSA SHA512 key",
			input: state.State{Google: google.Google{DNS: dns.DNS{
				ManagedZones: []dns.ManagedZone{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						DNSSec: dns.DNSSec{
							Metadata: trivyTypes.NewTestMetadata(),
							DefaultKeySpecs: []dns.KeySpecs{
								{
									Metadata:  trivyTypes.NewTestMetadata(),
									Algorithm: trivyTypes.String("rsasha512", trivyTypes.NewTestMetadata()),
									KeyType:   trivyTypes.String("keySigning", trivyTypes.NewTestMetadata()),
								},
								{
									Metadata:  trivyTypes.NewTestMetadata(),
									Algorithm: trivyTypes.String("rsasha512", trivyTypes.NewTestMetadata()),
									KeyType:   trivyTypes.String("zoneSigning", trivyTypes.NewTestMetadata()),
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
