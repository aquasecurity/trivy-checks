package main

import (
	"fmt"
	"os"

	// register Built-in Functions from defsec
	"github.com/aquasecurity/trivy-checks/pkg/rego"
	_ "github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/open-policy-agent/opa/cmd"
)

func main() {
	rego.RegisterBuiltins()
	// runs: opa test lib/ checks/
	if err := cmd.RootCommand.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
