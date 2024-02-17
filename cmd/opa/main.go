package main

import (
	"fmt"
	"os"

	_ "github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/open-policy-agent/opa/cmd"
)

func main() {
	if err := cmd.RootCommand.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
