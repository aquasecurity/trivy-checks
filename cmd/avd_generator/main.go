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

	"github.com/aquasecurity/defsec/pkg/framework"
	"github.com/aquasecurity/trivy-policies/rules"

	_ "github.com/aquasecurity/defsec/pkg/rego"
	registered "github.com/aquasecurity/defsec/pkg/rules"
	drules "github.com/aquasecurity/defsec/pkg/types/rules"
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
func writeDocsFile(meta drules.RegisteredRule, path string) {

	tmpl, err := template.New("defsec").Parse(docsMarkdownTemplate)
	if err != nil {
		fail("error occurred creating the template %v\n", err)
	}

	docpath := filepath.Join(path,
		strings.ToLower(meta.GetRule().Provider.ConstName()),
		strings.ToLower(strings.ReplaceAll(meta.GetRule().Service, "-", "")),
		meta.GetRule().AVDID,
	)

	if err := os.MkdirAll(docpath, os.ModePerm); err != nil {
		panic(err)
	}

	file, err := os.Create(filepath.Join(docpath, "docs.md"))
	if err != nil {
		fail("error occurred creating the docs file for %s", docpath)
	}

	if err := tmpl.Execute(file, meta.GetRule()); err != nil {
		fail("error occurred generating the document %v", err)
	}
	fmt.Printf("Generating docs file for policy %s\n", meta.GetRule().AVDID)

	if meta.GetRule().Terraform != nil {
		if len(meta.GetRule().Terraform.GoodExamples) > 0 || len(meta.GetRule().Terraform.Links) > 0 {
			if meta.GetRule().RegoPackage != "" { // get examples from file as rego rules don't have embedded
				value, err := GetExampleValueFromFile(meta.GetRule().Terraform.GoodExamples[0], "GoodExamples")
				if err != nil {
					fail("error retrieving examples from metadata: %v\n", err)
				}
				meta.GetRule().Terraform.GoodExamples = []string{value}
			}

			tmpl, err := template.New("terraform").Parse(terraformMarkdownTemplate)
			if err != nil {
				fail("error occurred creating the template %v\n", err)
			}
			file, err := os.Create(filepath.Join(docpath, "Terraform.md"))
			if err != nil {
				fail("error occurred creating the Terraform file for %s", docpath)
			}
			defer func() { _ = file.Close() }()

			if err := tmpl.Execute(file, meta.GetRule()); err != nil {
				fail("error occurred generating the document %v", err)
			}
			fmt.Printf("Generating Terraform file for policy %s\n", meta.GetRule().AVDID)
		}
	}

	if meta.GetRule().CloudFormation != nil {
		if len(meta.GetRule().CloudFormation.GoodExamples) > 0 || len(meta.GetRule().CloudFormation.Links) > 0 {
			if meta.GetRule().RegoPackage != "" { // get examples from file as rego rules don't have embedded
				value, err := GetExampleValueFromFile(meta.GetRule().CloudFormation.GoodExamples[0], "GoodExamples")
				if err != nil {
					fail("error retrieving examples from metadata: %v\n", err)
				}
				meta.GetRule().CloudFormation.GoodExamples = []string{value}
			}

			tmpl, err := template.New("cloudformation").Parse(cloudformationMarkdownTemplate)
			if err != nil {
				fail("error occurred creating the template %v\n", err)
			}
			file, err := os.Create(filepath.Join(docpath, "CloudFormation.md"))
			if err != nil {
				fail("error occurred creating the CloudFormation file for %s", docpath)
			}
			defer func() { _ = file.Close() }()

			if err := tmpl.Execute(file, meta.GetRule()); err != nil {
				fail("error occurred generating the document %v", err)
			}
			fmt.Printf("Generating CloudFormation file for policy %s\n", meta.GetRule().AVDID)
		}
	}
}

func fail(msg string, args ...interface{}) {
	fmt.Printf(msg, args...)
	os.Exit(1)
}

func readFileFromPolicyFS(path string) (io.Reader, error) {
	path = strings.TrimPrefix(path, "rules/")
	return rules.EmbeddedPolicyFileSystem.Open(path)

}

func GetExampleValueFromFile(filename string, exampleType string) (string, error) {
	r, err := readFileFromPolicyFS(filename)
	if err != nil {
		return "", err
	}
	f, err := parser.ParseFile(token.NewFileSet(), filename, r, parser.AllErrors)
	if err != nil {
		return "", err
	}

	for _, d := range f.Decls {
		switch decl := d.(type) {
		case *goast.GenDecl:
			for _, spec := range decl.Specs {
				switch spec := spec.(type) {
				case *goast.ValueSpec:
					for _, id := range spec.Names {
						switch v := id.Obj.Decl.(*goast.ValueSpec).Values[0].(type) {
						case *goast.CompositeLit:
							value := v.Elts[0].(*goast.BasicLit).Value
							if strings.Contains(id.Name, exampleType) {
								return strings.ReplaceAll(value, "`", ""), nil
							}
						}
					}
				}
			}
		}
	}
	return "", fmt.Errorf("exampleType %s not found in file: %s", exampleType, filename)
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
