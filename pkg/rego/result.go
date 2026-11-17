package rego

import (
	"iter"

	"github.com/aquasecurity/trivy-checks/internal/rego"
	opa "github.com/open-policy-agent/opa/v1/rego"
)

// Result is a finding reported by a check, built by the result.new built-in.
type Result = rego.Result

// ParseResults reads back the findings the checks reported. A rule that builds a set
// gives all of its findings in one expression, a complete rule gives a single one.
func ParseResults(rs opa.ResultSet) iter.Seq[Result] {
	return rego.ParseResults(rs)
}
