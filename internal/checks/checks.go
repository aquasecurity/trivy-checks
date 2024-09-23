package checks

import (
	"sort"

	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/rules"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
)

func LoadRegoChecks() []scan.Rule {
	// Clean up all Go checks
	rules.Reset()

	// Load Rego checks
	rego.LoadAndRegister()

	var res []scan.Rule

	for _, metadata := range rules.GetRegistered(framework.ALL) {
		res = append(res, metadata.Rule)
	}

	sort.Slice(res, func(i, j int) bool {
		return res[i].AVDID < res[j].AVDID
	})

	return res
}
