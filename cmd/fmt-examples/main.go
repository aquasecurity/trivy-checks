package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy-checks/internal/examples"
	"github.com/aquasecurity/trivy-checks/pkg/rego/metadata"
)

func main() {
	if err := run(); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}

func run() error {

	checksMetadata, err := metadata.LoadDefaultChecksMetadata()
	if err != nil {
		return fmt.Errorf("load checks metadata: %w", err)
	}

	for _, meta := range checksMetadata {
		if err := formatExamples(meta); err != nil {
			return err
		}
	}

	return nil
}

func formatExamples(meta metadata.Metadata) error {
	exmpls, path, err := examples.GetCheckExamples(meta)
	if err != nil {
		return err
	}

	if path == "" {
		return nil
	}

	exmpls.Format()
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := yaml.NewEncoder(f)
	enc.SetIndent(2)
	if err := enc.Encode(&exmpls); err != nil {
		return err
	}

	return nil
}
