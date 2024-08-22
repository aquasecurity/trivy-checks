package test

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud"
	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/dns"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(nifcloudDnsTestCases)
}

var nifcloudDnsTestCases = testCases{
	"AVD-NIF-0007": {
		{
			name:     "No records",
			input:    state.State{Nifcloud: nifcloud.Nifcloud{DNS: dns.DNS{}}},
			expected: false,
		},
		{
			name: "Some record",
			input: state.State{Nifcloud: nifcloud.Nifcloud{DNS: dns.DNS{
				Records: []dns.Record{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Type:     trivyTypes.String("A", trivyTypes.NewTestMetadata()),
						Record:   trivyTypes.String("some", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Some TXT record",
			input: state.State{Nifcloud: nifcloud.Nifcloud{DNS: dns.DNS{
				Records: []dns.Record{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Type:     trivyTypes.String("TXT", trivyTypes.NewTestMetadata()),
						Record:   trivyTypes.String("some", trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},

		{
			name: "Verify TXT record",
			input: state.State{Nifcloud: nifcloud.Nifcloud{DNS: dns.DNS{
				Records: []dns.Record{
					{
						Metadata: trivyTypes.NewTestMetadata(),
						Type:     trivyTypes.String("TXT", trivyTypes.NewTestMetadata()),
						Record:   trivyTypes.String(dns.ZoneRegistrationAuthTxt, trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
	},
}
