package test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy-checks/pkg/rego/metadata"
)

func TestAVDIDs(t *testing.T) {
	existing := make(map[string]struct{})

	checksMeta, err := metadata.LoadDefaultChecksMetadata()
	require.NoError(t, err)

	for path, meta := range checksMeta {
		id := meta.AVDID()
		t.Run(path, func(t *testing.T) {
			if id == "" {
				t.Errorf("Rule has no AVD ID: %#v", path)
				return
			}

			if _, ok := existing[id]; ok {
				t.Errorf("Rule detected with duplicate AVD ID: %s", id)
			}

			if !meta.Deprecated() {
				existing[id] = struct{}{}
			}
		})
	}
}
