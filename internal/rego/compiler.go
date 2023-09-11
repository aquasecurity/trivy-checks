package rego

import "github.com/open-policy-agent/opa/ast"

func NewRegoCompiler(schemas *ast.SchemaSet) *ast.Compiler {
	return ast.NewCompiler().
		WithUseTypeCheckAnnotations(true).
		WithCapabilities(ast.CapabilitiesForThisVersion()).
		WithSchemas(schemas)
}
