package rules

import (
	"github.com/aquasecurity/defsec/pkg/framework"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/simar7/trivy-misconf-rules/internal/rules"
)

func Register(rule scan.Rule, f scan.CheckFunc) rules.RegisteredRule {
	return rules.Register(rule, f)
}

func Deregister(rule rules.RegisteredRule) {
	rules.Deregister(rule)
}

func GetRegistered(fw ...framework.Framework) []rules.RegisteredRule {
	return rules.GetFrameworkRules(fw...)
}

func GetSpecRules(spec string) []rules.RegisteredRule {
	return rules.GetSpecRules(spec)
}
