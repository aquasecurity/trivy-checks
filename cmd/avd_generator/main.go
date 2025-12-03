package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/aquasecurity/trivy-checks/internal/examples"
	"github.com/aquasecurity/trivy-checks/pkg/rego/metadata"
)

const docsDir = "avd_docs"

func main() {
	if err := os.RemoveAll(docsDir); err != nil {
		panic(err)
	}
	generateDocs(docsDir)
}

func generateDocs(path string) {
	var generateCount int

	checksMetadata, err := metadata.LoadDefaultChecksMetadata()
	if err != nil {
		panic(err)
	}

	for _, meta := range checksMetadata {
		writeDocsFile(meta, path)
		generateCount++
	}

	fmt.Printf("\nGenerated %d files in %s\n", generateCount, path)
}

func writeDocsFile(meta metadata.Metadata, path string) {

	tmpl, err := template.New("defsec").Parse(docsMarkdownTemplate)
	if err != nil {
		fail("error occurred creating the template %v\n", err)
	}

	docpath := filepath.Join(path,
		strings.ToLower(meta.Provider().ConstName()),
		strings.ToLower(strings.ReplaceAll(meta.Service(), "-", "")),
		meta.ID(),
	)

	if err := os.MkdirAll(docpath, os.ModePerm); err != nil {
		panic(err)
	}

	file, err := os.Create(filepath.Join(docpath, "docs.md"))
	if err != nil {
		fail("error occurred creating the docs file for %s", docpath)
	}

	if err := tmpl.Execute(file, meta); err != nil {
		fail("error occurred generating the document %s", err.Error())
	}

	fmt.Printf("Generating docs file for policy %s\n", meta.ID())

	exmpls, path, err := examples.GetCheckExamples(meta)
	if err != nil {
		fail("failed to get check examples: %s", err.Error())
	}

	if path == "" {
		return
	}

	if err := generateExamplesDocs(meta, exmpls, docpath); err != nil {
		fail("error generating examples for terraform: %v\n", err)
	}
}

func generateExamplesDocs(meta metadata.Metadata, exmpls examples.CheckExamples, docpath string) error {
	for provider, providerExampls := range exmpls {
		if err := generateProviderExamplesDocs(meta, provider, providerExampls, docpath); err != nil {
			return fmt.Errorf("generating examples for %s: %v", provider, err)
		}
	}

	return nil
}

func generateProviderExamplesDocs(
	meta metadata.Metadata, provider string, providerExampls examples.ProviderExamples, docpath string,
) error {
	tmplContent, ok := templates[provider]
	if !ok {
		return nil
	}

	tmpl, err := template.New(strings.ToLower(provider)).Parse(tmplContent)
	if err != nil {
		return fmt.Errorf("create template: %w", err)
	}

	path := filepath.Join(docpath, fmt.Sprintf("%s.md", displayNameForProvider(provider)))
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}

	data := map[string]any{
		"Metadata": meta,
		"Examples": providerExampls,
	}

	if err := tmpl.Execute(file, data); err != nil {
		return fmt.Errorf("execute template: %w", err)
	}
	fmt.Printf("Generating %s file for policy %s\n", provider, meta.AVDID())

	return nil
}

func fail(msg string, args ...interface{}) {
	fmt.Printf(msg, args...)
	os.Exit(1)
}

var docsMarkdownTemplate = `
{{ .Description }}

### Impact
{{ if .Custom.impact }}{{ .Custom.impact }}{{ else }}<!-- Add Impact here -->{{ end }}

<!-- DO NOT CHANGE -->
{{ ` + "`{{ " + `remediationActions ` + "`}}" + `}}

{{ if .Links }}### Links{{ range .Links }}
- {{ . }}
{{ end}}
{{ end }}
`

var templates = map[string]string{
	"terraform":      terraformMarkdownTemplate,
	"cloudformation": cloudformationMarkdownTemplate,
}

var terraformMarkdownTemplate = `
{{ .Metadata.Custom.recommended_action }}

{{ if .Examples.Good }}{{ range .Examples.Good }}` + "```hcl" + `
{{ . }}
` + "```" + `
{{ end}}{{ end }}
{{ if .Examples.Links }}#### Remediation Links{{ range .Examples.Links }}
 - {{ . }}
{{ end}}{{ end }}
`

var cloudformationMarkdownTemplate = `
{{ .Metadata.Custom.recommended_action }}

{{ if .Examples.Good }}{{ range .Examples.Good }}` + "```yaml" + `
{{ . }}
` + "```" + `
{{ end}}{{ end }}
{{ if .Examples.Links }}#### Remediation Links{{ range .Examples.Links }}
 - {{ . }}
{{ end}}{{ end }}
`

func displayNameForProvider(provider string) string {
	switch provider {
	case "terraform":
		return "Terraform"
	case "cloudformation":
		return "CloudFormation"
	}
	return ""
}
