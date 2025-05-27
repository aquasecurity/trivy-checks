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
