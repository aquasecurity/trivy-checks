package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/aquasecurity/trivy-checks/internal/examples"
	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/rules"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	types "github.com/aquasecurity/trivy/pkg/iac/types/rules"
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

	// Clean up all Go checks
	rules.Reset()

	// Load Rego checks
	rego.LoadAndRegister()

	for _, metadata := range rules.GetRegistered(framework.ALL) {
		writeDocsFile(metadata, path)
		generateCount++
	}

	fmt.Printf("\nGenerated %d files in %s\n", generateCount, path)
}

func writeDocsFile(meta types.RegisteredRule, path string) {

	tmpl, err := template.New("defsec").Parse(docsMarkdownTemplate)
	if err != nil {
		fail("error occurred creating the template %v\n", err)
	}

	rule := meta.GetRule()

	docpath := filepath.Join(path,
		strings.ToLower(rule.Provider.ConstName()),
		strings.ToLower(strings.ReplaceAll(rule.Service, "-", "")),
		rule.AVDID,
	)

	if err := os.MkdirAll(docpath, os.ModePerm); err != nil {
		panic(err)
	}

	file, err := os.Create(filepath.Join(docpath, "docs.md"))
	if err != nil {
		fail("error occurred creating the docs file for %s", docpath)
	}

	if err := tmpl.Execute(file, rule); err != nil {
		fail("error occurred generating the document %s", err.Error())
	}
	fmt.Printf("Generating docs file for policy %s\n", rule.AVDID)

	exmpls, path, err := examples.GetCheckExamples(rule)
	if err != nil {
		fail("failed to get check examples: %s", err.Error())
	}

	if path == "" {
		return
	}

	if err := generateExamplesDocs(rule, exmpls, docpath); err != nil {
		fail("error generating examples for terraform: %v\n", err)
	}
}

func generateExamplesDocs(rule scan.Rule, exmpls examples.CheckExamples, docpath string) error {
	for provider, providerExampls := range exmpls {
		if err := generateProviderExamplesDocs(rule, provider, providerExampls, docpath); err != nil {
			return fmt.Errorf("generating examples for %s: %v", provider, err)
		}
	}

	return nil
}

func generateProviderExamplesDocs(
	rule scan.Rule, provider string, providerExampls examples.ProviderExamples, docpath string,
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
		"Rule":     rule,
		"Examples": providerExampls,
	}

	if err := tmpl.Execute(file, data); err != nil {
		return fmt.Errorf("execute template: %w", err)
	}
	fmt.Printf("Generating %s file for policy %s\n", provider, rule.AVDID)

	return nil
}

func fail(msg string, args ...interface{}) {
	fmt.Printf(msg, args...)
	os.Exit(1)
}

var docsMarkdownTemplate = `
{{ .Explanation }}

### Impact
{{ if .Impact }}{{ .Impact }}{{ else }}<!-- Add Impact here -->{{ end }}

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
{{ .Rule.Resolution }}

{{ if .Examples.Good }}{{ range .Examples.Good }}` + "```hcl" + `
{{ . }}
` + "```" + `
{{ end}}{{ end }}
{{ if .Examples.Links }}#### Remediation Links{{ range .Examples.Links }}
 - {{ . }}
{{ end}}{{ end }}
`

var cloudformationMarkdownTemplate = `
{{ .Rule.Resolution }}

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
