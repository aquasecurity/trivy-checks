package test

import (
	"context"
	"fmt"
	goast "go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	checks "github.com/aquasecurity/trivy-checks"
	rules "github.com/aquasecurity/trivy/pkg/iac/rules"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/cloudformation"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/terraform"
	"github.com/stretchr/testify/require"
)

func TestCheckExamples(t *testing.T) {
	tfScanner := terraform.New()
	cfScanner := cloudformation.New()

	for _, registeredRule := range rules.GetRegistered() {
		t.Run(registeredRule.AVDID, func(t *testing.T) {
			tfexamples := getExamplesFromRule(t, registeredRule.Rule, registeredRule.Terraform)
			for i, example := range tfexamples {
				t.Run(fmt.Sprintf("terraform_%d", i), func(t *testing.T) {
					scanExample(t, tfScanner, registeredRule.LongID(), example)
				})
			}

			cfexamples := getExamplesFromRule(t, registeredRule.Rule, registeredRule.CloudFormation)
			for i, example := range cfexamples {
				t.Run(fmt.Sprintf("cloudformation_%d", i), func(t *testing.T) {
					scanExample(t, cfScanner, registeredRule.LongID(), example)
				})
			}
		})
	}
}

type scanner interface {
	ScanFS(ctx context.Context, fsys fs.FS, dir string) (scan.Results, error)
}

func scanExample(t *testing.T, s scanner, checkID string, example example) {

	var filename string
	switch s.(type) {
	case *terraform.Scanner:
		filename = fmt.Sprintf("%s.tf", checkID)
	case *cloudformation.Scanner:
		filename = fmt.Sprintf("%s.yaml", checkID)
	}

	fsys := fstest.MapFS{
		filename: &fstest.MapFile{
			Data: []byte(example.content),
		},
	}

	res, err := s.ScanFS(context.TODO(), fsys, ".")
	require.NoError(t, err)
	contains := resultsContainsCheck(res, checkID, example.good)
	if !contains {
		exampleType := "good"
		if !example.good {
			exampleType = "bad"
		}
		t.Fatalf("results does not contain check %q for %s example: %s",
			checkID, exampleType, example.content)
	}
}

func resultsContainsCheck(results scan.Results, checkID string, good bool) bool {
	if good {
		results = results.GetPassed()
	} else {
		results = results.GetFailed()
	}

	for _, result := range results {
		if result.Rule().LongID() == checkID {
			return true
		}
	}

	return false
}

type example struct {
	content string
	good    bool
}

func getExamplesFromRule(t *testing.T, r scan.Rule, engine *scan.EngineMetadata) []example {
	if engine == nil {
		return nil
	}

	examples := getExamplesForType(t, r, engine.GoodExamples, "GoodExamples")
	examples = append(examples, getExamplesForType(t, r, engine.BadExamples, "BadExamples")...)
	return examples
}

func getExamplesForType(t *testing.T, r scan.Rule, files []string, exampleType string) []example {
	var res []example

	if r.RegoPackage != "" {
		for _, exampleFile := range files {
			contents, err := getExampleValuesFromFile(exampleFile, exampleType)
			if err != nil {
				require.NoError(t, err)
			}

			for _, content := range contents {
				res = append(res, example{
					content: content,
					good:    exampleType == "GoodExamples",
				})
			}
		}
	} else {
		for _, exampleFile := range files {
			res = append(res, example{
				content: exampleFile,
				good:    exampleType == "GoodExamples",
			})
		}
	}

	return res
}

func getExampleValuesFromFile(filename string, exampleType string) ([]string, error) {
	r, err := checks.EmbeddedPolicyFileSystem.Open(filename)
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
									if strings.HasSuffix(id.Name, exampleType) {
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
