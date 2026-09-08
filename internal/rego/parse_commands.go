package rego

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/topdown/builtins"
	"github.com/open-policy-agent/opa/v1/types"
	"mvdan.cc/sh/v3/syntax"
)

var ShParseCommandsDecl = &rego.Function{
	Name:        "sh.parse_commands",
	Decl:        types.NewFunction(types.Args(types.S), types.NewArray(nil, types.NewArray(nil, types.S))),
	Description: "Parse command sequence",
	Memoize:     true,
}

var ShParseCommandsImpl = func(_ rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
	astr, err := builtins.StringOperand(a.Value, 0)
	if err != nil {
		return nil, fmt.Errorf("invalid parameter type: %w", err)
	}

	commands, err := parseCommands(string(astr))

	if err != nil {
		return nil, fmt.Errorf("parse command sequence error: %w", err)
	}

	var commandsTerm []*ast.Term
	for _, cmd := range commands {
		var cmdTerm []*ast.Term
		for _, cmd_part := range cmd {
			cmdTerm = append(cmdTerm, ast.StringTerm(cmd_part))
		}
		commandsTerm = append(commandsTerm, ast.ArrayTerm(cmdTerm...))
	}

	return ast.ArrayTerm(commandsTerm...), nil
}

func parseCommands(cmdsSeq string) ([][]string, error) {
	f, err := syntax.NewParser().Parse(strings.NewReader(cmdsSeq), "")
	if err != nil {
		return nil, err
	}

	printer := syntax.NewPrinter()

	var buffer bytes.Buffer

	var commands [][]string
	for node := range syntax.Preorder(f) {
		call, ok := node.(*syntax.CallExpr)
		if !ok {
			continue
		}

		cmd := make([]string, 0, len(call.Args))
		for _, word := range call.Args {
			buffer.Reset()
			printer.Print(&buffer, word)
			cmd = append(cmd, buffer.String())
		}
		if len(cmd) > 0 {
			commands = append(commands, cmd)
		}
	}

	return commands, nil
}
