package test

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
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

func TestInputsConformToSchema(t *testing.T) {
	modules := collectModules(t)
	queries := buildEvalInputRules(t, modules)

	compiler := compileModules(t, modules)
	schemas := loadSchemas(t)

	for query, loc := range queries {
		ruleName := lo.LastOrEmpty(strings.Split(query, "."))
		t.Run(ruleName, func(t *testing.T) {
			res, err := evalRuleInput(t.Context(), compiler, query)
			require.NoError(t, err, query)
			require.Greater(t, len(res), 0)

			schema, err := schemaByPackage(schemas, query)
			require.NoError(t, err)

			for _, el := range res {
				documentLoader := gojsonschema.NewGoLoader(el)

				result, err := schema.Validate(documentLoader)
				require.NoError(t, err)

				if !result.Valid() {
					errs := lo.Map(result.Errors(), func(err gojsonschema.ResultError, _ int) string {
						return err.String()
					})
					abs, err := filepath.Abs(filepath.Join("..", loc))
					require.NoError(t, err)
					assert.True(t, false, fmt.Sprintf("%s\nAt %s", strings.Join(errs, "\n"), abs))
				}
			}
		})
	}
}

func collectModules(t *testing.T) map[string]*ast.Module {
	t.Helper()
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
	t.Helper()
	queries := make(map[string]string)

	for path, module := range modules {
		if !isTestRegoFile(path) {
			continue
		}

		if !module.Package.Path[1].Equal(ast.StringTerm("builtin")) {
			continue
		}

		copied := module.Copy()
		for _, r := range module.Rules {
			if !isTestRule(r) {
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

func isTestRule(r *ast.Rule) bool {
	return strings.HasPrefix(r.Head.Reference[0].String(), "test_")
}

func compileModules(t *testing.T, modules map[string]*ast.Module) *ast.Compiler {
	t.Helper()
	c := ast.NewCompiler()
	c.Compile(modules)
	require.Empty(t, c.Errors)
	return c
}

func loadSchemas(t *testing.T) map[string]*gojsonschema.Schema {
	t.Helper()

	return map[string]*gojsonschema.Schema{
		"cloud":      loadSchema(t, "../schemas/cloud.json", enforceNoAdditionalProperties),
		"kubernetes": loadSchema(t, "../schemas/kubernetes.json"),
		"dockerfile": loadSchema(t, "../schemas/dockerfile.json"),
	}
}

type patchFunc func(map[string]any)

func loadSchema(t *testing.T, filename string, patches ...patchFunc) *gojsonschema.Schema {
	t.Helper()

	bytes, err := os.ReadFile(filepath.Clean(filename))
	require.NoError(t, err)

	if len(patches) > 0 {
		var schemaMap map[string]any
		require.NoError(t, json.Unmarshal(bytes, &schemaMap))
		for _, patch := range patches {
			patch(schemaMap)
		}
		bytes, err = json.Marshal(schemaMap)
		require.NoError(t, err)
	}

	schema, err := gojsonschema.NewSchema(gojsonschema.NewBytesLoader(bytes))
	require.NoError(t, err)
	return schema
}

func enforceNoAdditionalProperties(schema map[string]any) {
	if schema["type"] == "object" {
		if _, ok := schema["additionalProperties"]; !ok {
			schema["additionalProperties"] = false
		}
	}

	for _, key := range []string{"properties", "definitions"} {
		if sub, ok := schema[key].(map[string]any); ok {
			for name, v := range sub {
				if key == "definitions" &&
					name == "github.com.aquasecurity.trivy.pkg.iac.types.MapValue" {
					continue
				}
				if m, ok := v.(map[string]any); ok {
					enforceNoAdditionalProperties(m)
				}
			}
		}
	}
}

func schemaByPackage(loaders map[string]*gojsonschema.Schema, pkg string) (*gojsonschema.Schema, error) {
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

func evalRuleInput(ctx context.Context, c *ast.Compiler, query string) ([]any, error) {
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

	val := rs[0].Expressions[0].Value
	arr, ok := val.([]any)
	if !ok {
		return nil, fmt.Errorf("expected array, but got %T", val)
	}
	return arr, nil
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
		for _, w := range expr.With {
			if w.Target.String() == "input" {
				newBody := ast.NewBody()
				for j := 0; j <= i-1; j++ {
					newBody.Append(rule.Body[j])
				}
				term := ast.MustParseExpr(fmt.Sprintf("res := %s", w.Value.String()))
				newBody.Append(term)
				newName := rule.Head.Reference[0].String() + "_eval_inp"
				refTerm := ast.VarTerm(newName)
				refTerm.SetLocation(ast.NewLocation([]byte(newName), "", -1, -1))
				newRule := &ast.Rule{
					Head: &ast.Head{
						Name:      ast.Var(newName),
						Reference: []*ast.Term{refTerm},
						Key:       ast.VarTerm("res"),
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

func isTestRegoFile(name string) bool {
	return strings.HasSuffix(name, "_test.rego")
}

func isDotFile(name string) bool {
	return strings.HasPrefix(name, ".")
}
