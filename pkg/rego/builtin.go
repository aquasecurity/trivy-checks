package rego

import (
	"sync"

	opa "github.com/open-policy-agent/opa/rego"
)

var registerOnce sync.Once

func RegisterBuiltins() {
	registerOnce.Do(func() {
		opa.RegisterBuiltin1(shParseCommandsDecl, shParseCommandsImpl)
	})
}
