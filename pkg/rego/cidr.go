package rego

import (
	"fmt"

	"github.com/aquasecurity/trivy-checks/internal/cidr"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown/builtins"
	"github.com/open-policy-agent/opa/types"
)

var cidrCountAdressesDecl = &rego.Function{
	Name:        "cidr.count_addresses",
	Decl:        types.NewFunction(types.Args(types.S), types.N),
	Description: "Count addresses",
	Memoize:     true,
}

var cidrCountAdressesImpl = func(_ rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	astr, err := builtins.StringOperand(a.Value, 0)
	if err != nil {
		return nil, fmt.Errorf("invalid parameter type: %w", err)
	}

	count := cidr.CountAddresses(string(astr))
	return ast.UIntNumberTerm(count), nil
}

var cidrIsPublicDecl = &rego.Function{
	Name:        "cidr.is_public",
	Decl:        types.NewFunction(types.Args(types.S), types.B),
	Description: "Is public",
	Memoize:     true,
}

var cidrIsPublicImpl = func(_ rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	astr, err := builtins.StringOperand(a.Value, 0)
	if err != nil {
		return nil, fmt.Errorf("invalid parameter type: %w", err)
	}

	isPublic := cidr.IsPublic(string(astr))
	return ast.BooleanTerm(isPublic), nil
}
