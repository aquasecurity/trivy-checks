package rego

import (
	"cmp"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/types"
)

// Keys of the object returned by the result.new built-in.
// Trivy reads the object back by these keys, so they must be changed in both projects.
const (
	resultKeyMessage      = "msg"
	resultKeyStartLine    = "startline"
	resultKeyEndLine      = "endline"
	resultKeySourcePrefix = "sourceprefix"
	resultKeyFilepath     = "filepath"
	resultKeyExplicit     = "explicit"
	resultKeyManaged      = "managed"
	resultKeyFSKey        = "fskey"
	resultKeyResource     = "resource"
	resultKeyParent       = "parent"
)

// metadataKey is the field where Trivy puts the location of a converted resource.
const metadataKey = "__defsec_metadata"

// Dockerfile commands keep the location in their own fields instead of metadataKey.
const (
	dockerKeyPath      = "Path"
	dockerKeyStartLine = "StartLine"
	dockerKeyEndLine   = "EndLine"
)

var ResultNewDecl = &rego.Function{
	Name:        "result.new",
	Decl:        types.NewFunction(types.Args(types.S, types.A), types.A),
	Description: "Build a check result with the metadata of the given resource",
}

var ResultNewImpl = createResult

// A resource is unmanaged when it did not come from the scanned code and Trivy filled it in
// itself, so a check has nothing to report on.
var IsManagedDecl = &rego.Function{
	Name:        "isManaged",
	Decl:        types.NewFunction(types.Args(types.A), types.B),
	Description: "Report whether the resource comes from the scanned code",
}

var IsManagedImpl = func(ctx rego.BuiltinContext, resource *ast.Term) (*ast.Term, error) {
	metadata, err := createResult(ctx, ast.StringTerm(""), resource)
	if err != nil {
		return nil, err
	}
	return metadata.Get(ast.StringTerm(resultKeyManaged)), nil
}

func createResult(ctx rego.BuiltinContext, msg, cause *ast.Term) (*ast.Term, error) {
	metadata := map[string]*ast.Term{
		resultKeyStartLine:    ast.IntNumberTerm(0),
		resultKeyEndLine:      ast.IntNumberTerm(0),
		resultKeySourcePrefix: ast.StringTerm(""),
		resultKeyFilepath:     ast.StringTerm(""),
		resultKeyExplicit:     ast.BooleanTerm(false),
		resultKeyManaged:      ast.BooleanTerm(true),
		resultKeyFSKey:        ast.StringTerm(""),
		resultKeyResource:     ast.StringTerm(""),
		resultKeyParent:       ast.NullTerm(),
	}
	if msg != nil {
		metadata[resultKeyMessage] = msg
	}

	// A converted struct keeps the location under metadataKey. A wrapped value or a
	// dockerfile command keeps it in its own top level fields instead.
	input := cmp.Or(cause.Get(ast.StringTerm(metadataKey)), cause)
	metadata = updateMetadata(metadata, input)

	if term := input.Get(ast.StringTerm(resultKeyParent)); term != nil {
		var err error
		metadata[resultKeyParent], err = createResult(ctx, nil, term)
		if err != nil {
			return nil, err
		}
	}

	values := make([][2]*ast.Term, 0, len(metadata))
	for key, val := range metadata {
		values = append(values, [2]*ast.Term{
			ast.StringTerm(key),
			val,
		})
	}
	return ast.ObjectTerm(values...), nil
}

// Fields of the input that the result inherits. A dockerfile command spells them
// differently, and its spelling comes later so that it wins.
var inheritedFields = []struct {
	from string
	to   string
}{
	{resultKeyStartLine, resultKeyStartLine},
	{dockerKeyStartLine, resultKeyStartLine},
	{resultKeyEndLine, resultKeyEndLine},
	{dockerKeyEndLine, resultKeyEndLine},
	{resultKeyFilepath, resultKeyFilepath},
	{dockerKeyPath, resultKeyFilepath},
	{resultKeySourcePrefix, resultKeySourcePrefix},
	{resultKeyExplicit, resultKeyExplicit},
	{resultKeyManaged, resultKeyManaged},
	{resultKeyFSKey, resultKeyFSKey},
	{resultKeyResource, resultKeyResource},
}

func updateMetadata(metadata map[string]*ast.Term, input *ast.Term) map[string]*ast.Term {
	for _, field := range inheritedFields {
		if term := input.Get(ast.StringTerm(field.from)); term != nil {
			metadata[field.to] = term
		}
	}
	return metadata
}
