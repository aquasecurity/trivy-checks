//go:build integration

package integration

import (
	"os"
)

func init() {
	os.Setenv("TESTCONTAINERS_RYUK_DISABLED", "true")
}
