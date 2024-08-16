package rego

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/topdown/builtins"
	"github.com/open-policy-agent/opa/types"
	"mvdan.cc/sh/v3/syntax"
)

var shParseCommandsDecl = &rego.Function{
	Name:        "sh.parse_commands",
	Decl:        types.NewFunction(types.Args(types.S), types.NewArray(nil, types.NewArray(nil, types.S))),
	Description: "Parse command sequence",
	Memoize:     true,
}

var shParseCommandsImpl = func(_ rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
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

	var commands [][]string
	syntax.Walk(f, func(node syntax.Node) bool {
		switch x := node.(type) {
		case *syntax.CallExpr:
			args := x.Args
			var cmd []string
			for _, word := range args {
				var buffer bytes.Buffer
				printer.Print(&buffer, word)
				cmd = append(cmd, buffer.String())
			}
			if cmd != nil {
				commands = append(commands, cmd)
			}
		}
		return true
	})

	return commands, nil
}
