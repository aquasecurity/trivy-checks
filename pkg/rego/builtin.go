package rego

import (
	"sync"

	"github.com/aquasecurity/trivy-checks/internal/rego"
	opa "github.com/open-policy-agent/opa/v1/rego"
)

var registerOnce sync.Once

func RegisterBuiltins() {
	registerOnce.Do(func() {
		opa.RegisterBuiltin1(rego.ShParseCommandsDecl, rego.ShParseCommandsImpl)
		opa.RegisterBuiltin1(rego.CidrCountAdressesDecl, rego.CidrCountAdressesImpl)
		opa.RegisterBuiltin1(rego.CidrIsPublicDecl, rego.CidrIsPublicImpl)
		opa.RegisterBuiltin1(rego.SquealerScanStringDecl, rego.SquealerScanStringImpl)
		opa.RegisterBuiltin2(rego.NewResultDecl, rego.NewResultImpl)
		opa.RegisterBuiltin1(rego.IsManagedDecl, rego.IsManagedImpl)
	})
}
