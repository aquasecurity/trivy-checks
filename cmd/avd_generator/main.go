package main

import (
	"fmt"
	goast "go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	policies "github.com/aquasecurity/trivy-checks"
	"github.com/aquasecurity/trivy/pkg/iac/framework"
	_ "github.com/aquasecurity/trivy/pkg/iac/rego"
	registered "github.com/aquasecurity/trivy/pkg/iac/rules"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	types "github.com/aquasecurity/trivy/pkg/iac/types/rules"
)

func main() {
	var generateCount int

	for _, metadata := range registered.GetRegistered(framework.ALL) {
		writeDocsFile(metadata, "avd_docs")
		generateCount++
	}

	fmt.Printf("\nGenerated %d files in avd_docs\n", generateCount)
}

// nolint: cyclop
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
		fail("error occurred generating the document %v", err)
	}
	fmt.Printf("Generating docs file for policy %s\n", rule.AVDID)

	if err := generateExamplesForEngine(rule, rule.Terraform, docpath, terraformMarkdownTemplate, "Terraform"); err != nil {
		fail("error generating examples for terraform: %v\n", err)
	}

	if err := generateExamplesForEngine(rule, rule.CloudFormation, docpath, cloudformationMarkdownTemplate, "CloudFormation"); err != nil {
		fail("error generating examples for cloudformation: %v\n", err)
	}
}

func generateExamplesForEngine(rule scan.Rule, engine *scan.EngineMetadata, docpath, tpl, provider string) error {
	if engine == nil {
		return nil
	}

	if len(engine.GoodExamples) == 0 {
		return nil
	}

	if rule.RegoPackage != "" { // get examples from file as rego rules don't have embedded
		examples, err := GetExampleValuesFromFile(engine.GoodExamples[0], "GoodExamples")
		if err != nil {
			fail("error retrieving examples from metadata: %v\n", err)
		}
		engine.GoodExamples = examples
	}

	tmpl, err := template.New(strings.ToLower(provider)).Parse(tpl)
	if err != nil {
		fail("error occurred creating the template %v\n", err)
	}
	file, err := os.Create(filepath.Join(docpath, fmt.Sprintf("%s.md", provider)))
	if err != nil {
		fail("error occurred creating the %s file for %s", provider, docpath)
	}
	defer func() { _ = file.Close() }()

	if err := tmpl.Execute(file, rule); err != nil {
		fail("error occurred generating the document %v", err)
	}
	fmt.Printf("Generating %s file for policy %s\n", provider, rule.AVDID)

	return nil
}

func fail(msg string, args ...interface{}) {
	fmt.Printf(msg, args...)
	os.Exit(1)
}

func readFileFromPolicyFS(path string) (io.Reader, error) {
	path = strings.TrimPrefix(path, "rules/")
	return policies.EmbeddedPolicyFileSystem.Open(path)

}

func GetExampleValuesFromFile(filename string, exampleType string) ([]string, error) {
	r, err := readFileFromPolicyFS(filename)
	if err != nil {
		return nil, err
	}
	f, err := parser.ParseFile(token.NewFileSet(), filename, r, parser.AllErrors)
	if err != nil {
		return nil, err
	}

	res := []string{}

	for _, d := range f.Decls {
		switch decl := d.(type) {
		case *goast.GenDecl:
			for _, spec := range decl.Specs {
				switch spec := spec.(type) {
				case *goast.ValueSpec:
					for _, id := range spec.Names {
						switch v := id.Obj.Decl.(*goast.ValueSpec).Values[0].(type) {
						case *goast.CompositeLit:
							for _, e := range v.Elts {
								switch e := e.(type) {
								case *goast.BasicLit:
									if strings.Contains(id.Name, exampleType) {
										res = append(res, strings.ReplaceAll(e.Value, "`", ""))
									}
								}
							}
						}
					}
				}
			}
		}
	}

	if len(res) == 0 {
		return nil, fmt.Errorf("exampleType %s not found in file: %s", exampleType, filename)
	}

	return res, nil
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

var terraformMarkdownTemplate = `
{{ .Resolution }}

{{ if .Terraform.GoodExamples }}{{ range .Terraform.GoodExamples }}` + "```hcl" + `{{ . }}
` + "```" + `
{{ end}}{{ end }}
{{ if .Terraform.Links }}#### Remediation Links{{ range .Terraform.Links }}
 - {{ . }}
{{ end}}{{ end }}
`

var cloudformationMarkdownTemplate = `
{{ .Resolution }}

{{ if .CloudFormation.GoodExamples }}{{ range .CloudFormation.GoodExamples }}` + "```yaml" + `{{ . }}
` + "```" + `
{{ end}}{{ end }}
{{ if .CloudFormation.Links }}#### Remediation Links{{ range .CloudFormation.Links }}
 - {{ . }}
{{ end}}{{ end }}
`
