//go:build integration

package integration

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func init() {
	os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")
}

func readTrivyReport(t *testing.T, outputFile string) []Result {
	t.Helper()

	out, err := os.ReadFile(outputFile)
	require.NoError(t, err)

	var wrapper struct {
		Results []Result `json:"Results"`
	}
	require.NoError(t, json.Unmarshal(out, &wrapper))

	return wrapper.Results
}

type Result struct {
	Target            string             `json:"Target"`
	Misconfigurations []Misconfiguration `json:"Misconfigurations"`
}

type Misconfiguration struct {
	ID     string `json:"ID"`
	Status string `json:"Status"`
}

func getFailureIDs(results []Result) map[string]map[string]struct{} {
	ids := make(map[string]map[string]struct{})

	for _, result := range results {
		for _, misconf := range result.Misconfigurations {
			if misconf.Status == "FAIL" {
				if _, ok := ids[result.Target]; !ok {
					ids[result.Target] = make(map[string]struct{})
				}
				ids[result.Target][misconf.ID] = struct{}{}
			}
		}
	}

	return ids
}
