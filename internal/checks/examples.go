package checks

import (
	goast "go/ast"
	"go/parser"
	"go/token"
	"strings"

	trivy_checks "github.com/aquasecurity/trivy-checks"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
)

type Provider string

const (
	TerraformProvider      Provider = "Terraform"
	CloudFormationProvider Provider = "CloudFormation"
)

func providerByFileName(n string) Provider {
	switch {
	case strings.HasSuffix(n, "tf.go"):
		return TerraformProvider
	case strings.HasSuffix(n, "cf.go"):
		return CloudFormationProvider
	}

	panic("unreachable")
}

type Example struct {
	Path        string
	Provider    Provider
	GoodExample bool // bad example if false
	Content     string
}

func GetCheckExamples(check scan.Rule) ([]*Example, error) {
	var files []string
	if check.Terraform != nil {
		files = append(files, check.Terraform.BadExamples...)
		// files = append(files, check.Terraform.GoodExamples...)
	}

	if check.CloudFormation != nil {
		files = append(files, check.CloudFormation.BadExamples...)
		// files = append(files, check.CloudFormation.GoodExamples...)
	}

	var res []*Example

	if check.RegoPackage != "" {
		for _, path := range files {
			exmpls, err := parseExamplesFromFile(path)
			if err != nil {
				return nil, err
			}

			res = append(res, exmpls...)
		}
	}

	return res, nil
}

func parseExamplesFromFile(filename string) ([]*Example, error) {
	r, err := trivy_checks.EmbeddedPolicyFileSystem.Open(filename)
	if err != nil {
		return nil, err
	}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, r, parser.AllErrors)
	if err != nil {
		return nil, err
	}
	return extractExamples(f, filename), nil
}

func extractExamples(f *goast.File, filename string) (res []*Example) {
	goast.Inspect(f, func(n goast.Node) bool {
		valueSpec, ok := n.(*goast.ValueSpec)
		if !ok {
			return true
		}

		for _, id := range valueSpec.Names {
			if !isExampleName(id.Name) {
				continue
			}

			if compositeLit, ok := valueSpec.Values[0].(*goast.CompositeLit); ok {
				for _, e := range compositeLit.Elts {
					if basicLit, ok := e.(*goast.BasicLit); ok {
						res = append(res, &Example{
							Path:        filename,
							GoodExample: strings.HasSuffix(id.Name, "GoodExamples"),
							Provider:    providerByFileName(filename),
							Content:     cleanupExample(basicLit.Value),
						})
					}
				}
			}
		}
		return true
	})

	return res
}

func isExampleName(name string) bool {
	return strings.HasSuffix(name, "GoodExamples") || strings.HasSuffix(name, "BadExamples")
}

func cleanupExample(s string) string {
	return strings.ReplaceAll(s, "`", "")
}
