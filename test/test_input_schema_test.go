package test

import (
	"context"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/loader"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xeipuuv/gojsonschema"

	trivy_checks "github.com/aquasecurity/trivy-checks"
	_ "github.com/aquasecurity/trivy/pkg/iac/rego" // register Built-in Functions from Trivy
)

func TestTestInputsConformToSchema(t *testing.T) {
	modules := collectModules(t)
	queries := buildEvalInputRules(t, modules)

	compiler := compileModules(t, modules)
	schemaLoaders := loadSchemaLoaders(t)

	for query, loc := range queries {
		ruleName := lo.LastOrEmpty(strings.Split(query, "."))
		t.Run(ruleName, func(t *testing.T) {
			res, err := evalRuleInput(t.Context(), compiler, query)
			require.NoError(t, err, query)

			schemaLoader, err := loaderByPackage(schemaLoaders, query)
			require.NoError(t, err)

			documentLoader := gojsonschema.NewGoLoader(res)
			result, err := gojsonschema.Validate(schemaLoader, documentLoader)
			require.NoError(t, err)

			if !result.Valid() {
				errs := lo.Map(result.Errors(), func(err gojsonschema.ResultError, _ int) string {
					return err.String()
				})
				assert.True(t, false, fmt.Sprintf("%s\nAt %s", strings.Join(errs, "\n"), loc))
			}
		})
	}
}

func collectModules(t *testing.T) map[string]*ast.Module {
	res1, err := loadModules(trivy_checks.EmbeddedPolicyFileSystem)
	require.NoError(t, err)

	res2, err := loadModules(trivy_checks.EmbeddedLibraryFileSystem)
	require.NoError(t, err)

	modules := make(map[string]*ast.Module)
	maps.Copy(modules, res1.ParsedModules())
	maps.Copy(modules, res2.ParsedModules())
	return modules
}

func buildEvalInputRules(t *testing.T, modules map[string]*ast.Module) map[string]string {
	queries := make(map[string]string)

	for path, module := range modules {
		if !testRegoFile(path) {
			continue
		}

		if !module.Package.Path[1].Equal(ast.StringTerm("builtin")) {
			continue
		}

		copied := module.Copy()
		for _, r := range module.Rules {
			if !strings.HasPrefix(r.Head.Name.String(), "test_") {
				continue
			}
			newRule := generateEvalInpRule(t, r)
			if newRule == nil {
				continue
			}

			copied.Rules = append(copied.Rules, newRule)
			query := module.Package.Path.String() + "." + newRule.Head.Name.String()
			queries[query] = r.Head.Location.String()
		}
		modules[path] = copied
	}
	return queries
}

func compileModules(t *testing.T, modules map[string]*ast.Module) *ast.Compiler {
	c := ast.NewCompiler()
	c.Compile(modules)
	require.Empty(t, c.Errors)
	return c
}

func loadSchemaLoaders(t *testing.T) map[string]gojsonschema.JSONLoader {
	load := func(filename string) gojsonschema.JSONLoader {
		bytes, err := os.ReadFile(filepath.Join("..", "schemas", filename))
		require.NoError(t, err)
		return gojsonschema.NewBytesLoader(bytes)
	}
	return map[string]gojsonschema.JSONLoader{
		"cloud":      load("cloud.json"),
		"kubernetes": load("kubernetes.json"),
		"dockerfile": load("dockerfile.json"),
	}
}

func loaderByPackage(loaders map[string]gojsonschema.JSONLoader, pkg string) (gojsonschema.JSONLoader, error) {
	parts := strings.Split(pkg, ".")
	switch parts[2] {
	case "aws", "azure", "google", "cloudstack", "oracle",
		"nifcloud", "openstack", "digitalocean", "github":
		return loaders["cloud"], nil
	case "kubernetes", "kube":
		return loaders["kubernetes"], nil
	case "dockerfile":
		return loaders["dockerfile"], nil
	default:
		return nil, fmt.Errorf("unknown source: %s", parts[2])
	}
}

func evalRuleInput(ctx context.Context, c *ast.Compiler, query string) (any, error) {
	r := rego.New(
		rego.Query(query),
		rego.Compiler(c),
	)

	rs, err := r.Eval(ctx)
	if err != nil {
		return nil, err
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, fmt.Errorf("bad result: %v", rs)
	}

	return rs[0].Expressions[0].Value, nil
}

func loadModules(fsys fs.FS) (*loader.Result, error) {
	return loader.NewFileLoader().
		WithFS(fsys).
		Filtered([]string{"."}, func(abspath string, info fs.FileInfo, depth int) bool {
			return isNotRegoFile(info)
		})
}

func generateEvalInpRule(t *testing.T, rule *ast.Rule) *ast.Rule {
	if lo.CountBy(rule.Body, func(expr *ast.Expr) bool {
		return slices.ContainsFunc(expr.With, func(w *ast.With) bool {
			return w.Target.String() == "input"
		})
	}) > 1 {
		t.Logf("Skip rule %q because it has more than one `with input as` clause", rule.Head.Name.String())
		return nil
	}

	for i, expr := range rule.Body {
		for k, w := range expr.With {
			if w.Target.String() == "input" {
				newBody := ast.NewBody()
				for j := 0; j <= i-1; j++ {
					newBody.Append(rule.Body[j])
				}
				term := ast.MustParseExpr(fmt.Sprintf("res := %s", w.Value.String()))
				newBody.Append(term)
				newName := rule.Head.Name.String() + strconv.Itoa(k) + "_eval_inp"
				newRule := &ast.Rule{
					Head: &ast.Head{
						Name:  ast.Var(newName),
						Value: ast.NewTerm(ast.Var("res")),
					},
					Body: newBody,
				}
				return newRule
			}
		}
	}

	return nil
}

func isNotRegoFile(fi fs.FileInfo) bool {
	return !fi.IsDir() && (!isRegoFile(fi.Name()) || isDotFile(fi.Name()))
}

func isRegoFile(name string) bool {
	return strings.HasSuffix(name, ".rego")
}

func testRegoFile(name string) bool {
	return strings.HasSuffix(name, "_test.rego")
}

func isDotFile(name string) bool {
	return strings.HasPrefix(name, ".")
}
