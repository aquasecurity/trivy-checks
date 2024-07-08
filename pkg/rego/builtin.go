package rego

import (
	"sync"

	opa "github.com/open-policy-agent/opa/rego"
)

var registerOnce sync.Once

func RegisterBuiltins() {
	registerOnce.Do(func() {
		opa.RegisterBuiltin1(shParseCommandsDecl, shParseCommandsImpl)
		opa.RegisterBuiltin1(cidrCountAdressesDecl, cidrCountAdressesImpl)
		opa.RegisterBuiltin1(cidrIsPublicDecl, cidrIsPublicImpl)
		opa.RegisterBuiltin1(squealerScanStringDecl, squealerScanStringImpl)
	})
}
