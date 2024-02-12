package documentdb

import (
	"testing"

	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/state"

	"github.com/aquasecurity/trivy/pkg/iac/providers/aws/documentdb"
	"github.com/aquasecurity/trivy/pkg/iac/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableStorageEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    documentdb.DocumentDB
		expected bool
	}{
		{
			name: "DocDB unencrypted storage",
			input: documentdb.DocumentDB{
				Clusters: []documentdb.Cluster{
					{
						Metadata:         defsecTypes.NewTestMetadata(),
						StorageEncrypted: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "DocDB encrypted storage",
			input: documentdb.DocumentDB{
				Clusters: []documentdb.Cluster{
					{
						Metadata:         defsecTypes.NewTestMetadata(),
						StorageEncrypted: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.DocumentDB = test.input
			results := CheckEnableStorageEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableStorageEncryption.LongID() {
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
