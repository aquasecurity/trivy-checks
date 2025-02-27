//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/commands"
	"github.com/aquasecurity/trivy/pkg/types"
)

func init() {
	os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")
}

func runTrivy(t *testing.T, args []string) {
	defer viper.Reset()

	t.Helper()

	app := commands.NewApp()
	app.SetOut(io.Discard)
	app.SetArgs(args)

	err := app.ExecuteContext(context.TODO())
	require.NoError(t, err)
}

func readTrivyReport(t *testing.T, outputFile string) types.Report {
	t.Helper()

	out, err := os.ReadFile(outputFile)
	require.NoError(t, err)

	var report types.Report
	require.NoError(t, json.Unmarshal(out, &report))
	return report
}
