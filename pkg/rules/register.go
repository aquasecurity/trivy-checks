package rules

import (
	"github.com/aquasecurity/defsec/pkg/framework"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/simar7/trivy-policies/internal/rules"
	"github.com/simar7/trivy-policies/pkg/types"
)

func Register(rule scan.Rule, f scan.CheckFunc) types.RegisteredRule {
	return rules.Register(rule, f)
}

func Deregister(rule types.RegisteredRule) {
	rules.Deregister(rule)
}

func GetRegistered(fw ...framework.Framework) []types.RegisteredRule {
	return rules.GetFrameworkRules(fw...)
}

func GetSpecRules(spec string) []types.RegisteredRule {
	return rules.GetSpecRules(spec)
}
