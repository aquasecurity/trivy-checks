package rego

import (
	"fmt"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown/builtins"
	"github.com/open-policy-agent/opa/types"
	"github.com/owenrumney/squealer/pkg/squealer"
)

var squealerScanStringDecl = &rego.Function{
	Name: "squealer.scan_string",
	Decl: types.NewFunction(types.Args(types.S), types.NewObject([]*types.StaticProperty{
		{Key: "transgressionFound", Value: types.NewBoolean()},
		{Key: "description", Value: types.NewString()},
	}, nil)),
	Description: "Scan string",
	Memoize:     true,
}

var squealerScanStringImpl = func(_ rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	astr, err := builtins.StringOperand(a.Value, 0)
	if err != nil {
		return nil, fmt.Errorf("invalid parameter type: %w", err)
	}

	scanner := squealer.NewStringScanner()
	result := scanner.Scan(string(astr))

	return ast.ObjectTerm(
		ast.Item(ast.StringTerm("transgressionFound"), ast.BooleanTerm(result.TransgressionFound)),
		ast.Item(ast.StringTerm("description"), ast.StringTerm(result.Description)),
	), nil
}
