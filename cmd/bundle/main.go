package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/aquasecurity/trivy-checks/internal/bundler"
)

func main() {
	root := flag.String("root", ".", "Root directory containing files to bundle")
	output := flag.String("out", "bundle.tar.gz", "Output archive file path")
	flag.Parse()

	log.Printf("Building bundle from root %q to %q", *root, *output)
	if err := buildBundle(*root, *output); err != nil {
		log.Fatalf("Error: %v", err)
	}
	log.Printf("Bundle %q successfully created", *output)
}

func buildBundle(root, outFile string) error {
	b := bundler.New(".", os.DirFS(root))

	f, err := os.Create(outFile)
	if err != nil {
		return fmt.Errorf("create archive file: %w", err)
	}
	defer f.Close()

	if err := b.Build(f); err != nil {
		return fmt.Errorf("build bundle: %w", err)
	}
	return nil
}
