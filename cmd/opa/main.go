package main

import (
	"os"

	"github.com/open-policy-agent/opa/cmd"

	"github.com/aquasecurity/trivy-checks/pkg/rego"
)

func main() {
	rego.RegisterBuiltins()
	// runs: opa test lib/ checks/
	if err := cmd.RootCommand.Execute(); err != nil {
		os.Exit(1)
	}
}
