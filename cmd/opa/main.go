package main

import (
	"fmt"
	"os"

	"github.com/open-policy-agent/opa/cmd"

	"github.com/aquasecurity/trivy-checks/pkg/rego"
	_ "github.com/aquasecurity/trivy/pkg/iac/rego" // register Built-in Functions from Trivy
)

func main() {
	rego.RegisterBuiltins()
	// runs: opa test lib/ checks/
	if err := cmd.RootCommand.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
