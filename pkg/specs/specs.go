package specs

import "github.com/aquasecurity/trivy-checks/pkg/compliance"

// Deprecated: use compliance.GetSpec
var GetSpec = compliance.GetSpec

// Deprecated: use compliance.Loader
type Loader = compliance.Loader

// Deprecated: use compliance.NewSpecLoader
func NewSpecLoader() Loader {
	return compliance.NewSpecLoader()
}
