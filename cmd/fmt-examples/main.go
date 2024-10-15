package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy-checks/internal/examples"
	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/rules"
)

func main() {
	if err := run(); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}

func run() error {
	// Clean up all Go checks
	rules.Reset()

	// Load Rego checks
	rego.LoadAndRegister()

	for _, r := range rules.GetRegistered(framework.ALL) {
		exmpls, path, err := examples.GetCheckExamples(r.Rule)
		if err != nil {
			return err
		}

		if path == "" {
			continue
		}

		exmpls.Format()
		f, err := os.Create(path)
		if err != nil {
			return err
		}

		enc := yaml.NewEncoder(f)
		enc.SetIndent(2)
		if err := enc.Encode(&exmpls); err != nil {
			f.Close()
			return err
		}
		f.Close()
	}

	return nil
}
