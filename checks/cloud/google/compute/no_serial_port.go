package compute

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckNoSerialPort = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0032",
		Provider:    providers.GoogleProvider,
		Service:     "compute",
		ShortCode:   "no-serial-port",
		Summary:     "Disable serial port connectivity for all instances",
		Impact:      "Unrestricted network access to the serial console of the instance",
		Resolution:  "Disable serial port access",
		Explanation: `When serial port access is enabled, the access is not governed by network security rules meaning the port can be exposed publicly.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoSerialPortGoodExamples,
			BadExamples:         terraformNoSerialPortBadExamples,
			Links:               terraformNoSerialPortLinks,
			RemediationMarkdown: terraformNoSerialPortRemediationMarkdown,
		},
		Severity:   severity.Medium,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, instance := range s.Google.Compute.Instances {
			if instance.Metadata.IsUnmanaged() {
				continue
			}
			if instance.EnableSerialPort.IsTrue() {
				results.Add(
					"Instance has serial port enabled.",
					instance.EnableSerialPort,
				)
			} else {
				results.AddPassed(&instance)
			}
		}
		return
	},
)
