package rego

import (
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/topdown/builtins"
	"github.com/open-policy-agent/opa/v1/types"
	"mvdan.cc/sh/v3/syntax"
)

var ShHasPipesDecl = &rego.Function{
	Name:        "sh.has_pipes",
	Decl:        types.NewFunction(types.Args(types.S), types.B),
	Description: "Check if command sequence contains a pipe operator",
	Memoize:     true,
}

var ShHasPipesImpl = func(_ rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	astr, err := builtins.StringOperand(a.Value, 0)
	if err != nil {
		return nil, fmt.Errorf("invalid parameter type: %w", err)
	}

	result, err := hasPipes(string(astr))
	if err != nil {
		return nil, fmt.Errorf("parse pipe error: %w", err)
	}

	return ast.BooleanTerm(result), nil
}

func hasPipes(cmdsSeq string) (bool, error) {
	f, err := syntax.NewParser().Parse(strings.NewReader(cmdsSeq), "")
	if err != nil {
		return false, err
	}

	hasPipe := false
	syntax.Walk(f, func(node syntax.Node) bool {
		if x, ok := node.(*syntax.BinaryCmd); ok {
			if x.Op == syntax.Pipe {
				hasPipe = true
				return false
			}
		}
		return true
	})
	return hasPipe, nil
}
