package gke

import (
	"testing"

	trivyTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/google/gke"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoLegacyAuthentication(t *testing.T) {
	tests := []struct {
		name     string
		input    gke.GKE
		expected bool
	}{
		{
			name: "Cluster master authentication by certificate",
			input: gke.GKE{
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
			},
			expected: true,
		},
		{
			name: "Cluster master authentication by username/password",
			input: gke.GKE{
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
			},
			expected: true,
		},
		{
			name: "Cluster master authentication by certificate or username/password disabled",
			input: gke.GKE{
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
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Google.GKE = test.input
			results := CheckNoLegacyAuthentication.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoLegacyAuthentication.LongID() {
					found = true
				}
			}
			if test.expected {
				assert.True(t, found, "Rule should have been found")
			} else {
				assert.False(t, found, "Rule should not have been found")
			}
		})
	}
}
