//go:build integration

package integration

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/types"
)

func init() {
	os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")
}

func readTrivyReport(t *testing.T, outputFile string) types.Report {
	t.Helper()

	out, err := os.ReadFile(outputFile)
	require.NoError(t, err)

	var report types.Report
	require.NoError(t, json.Unmarshal(out, &report))
	return report
}

func getFailureIDs(report types.Report) map[string][]string {
	ids := make(map[string][]string)

	for _, result := range report.Results {
		for _, misconf := range result.Misconfigurations {
			if misconf.Status == types.MisconfStatusFailure {
				ids[result.Target] = append(ids[result.Target], misconf.AVDID)
			}
		}
	}

	return ids
}
