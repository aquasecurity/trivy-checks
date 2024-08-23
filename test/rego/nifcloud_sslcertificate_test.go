package test

import (
	"time"

	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud"
	"github.com/aquasecurity/trivy/pkg/iac/providers/nifcloud/sslcertificate"
	"github.com/aquasecurity/trivy/pkg/iac/state"
	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func init() {
	addTests(nifcloudSslCertificateTestCases)
}

var nifcloudSslCertificateTestCases = testCases{
	"AVD-NIF-0006": {
		{
			name:     "No certs",
			input:    state.State{Nifcloud: nifcloud.Nifcloud{SSLCertificate: sslcertificate.SSLCertificate{}}},
			expected: false,
		},
		{
			name: "Valid cert",
			input: state.State{Nifcloud: nifcloud.Nifcloud{SSLCertificate: sslcertificate.SSLCertificate{
				ServerCertificates: []sslcertificate.ServerCertificate{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Expiration: trivyTypes.Time(time.Now().Add(time.Hour), trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Expired cert",
			input: state.State{Nifcloud: nifcloud.Nifcloud{SSLCertificate: sslcertificate.SSLCertificate{
				ServerCertificates: []sslcertificate.ServerCertificate{
					{
						Metadata:   trivyTypes.NewTestMetadata(),
						Expiration: trivyTypes.Time(time.Now().Add(-time.Hour), trivyTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
	},
}
