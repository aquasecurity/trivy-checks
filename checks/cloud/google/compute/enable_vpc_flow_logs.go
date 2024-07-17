package compute

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckEnableVPCFlowLogs = rules.Register(
	scan.Rule{
		AVDID:       "AVD-GCP-0029",
		Provider:    providers.GoogleProvider,
		Service:     "compute",
		ShortCode:   "enable-vpc-flow-logs",
		Summary:     "VPC flow logs should be enabled for all subnetworks",
		Impact:      "Limited auditing capability and awareness",
		Resolution:  "Enable VPC flow logs",
		Explanation: `VPC flow logs record information about all traffic, which is a vital tool in reviewing anomalous traffic.`,
		Links:       []string{},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableVpcFlowLogsGoodExamples,
			BadExamples:         terraformEnableVpcFlowLogsBadExamples,
			Links:               terraformEnableVpcFlowLogsLinks,
			RemediationMarkdown: terraformEnableVpcFlowLogsRemediationMarkdown,
		},
		Severity:   severity.Low,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, network := range s.Google.Compute.Networks {
			for _, subnetwork := range network.Subnetworks {
				if subnetwork.EnableFlowLogs.IsFalse() &&
					// Proxy-only subnets don't support VPC Flow Logs.
					// https://cloud.google.com/vpc/docs/using-flow-logs#flow_logs_appear_to_be_disabled_even_though_you_enabled_them
					!subnetwork.Purpose.IsOneOf("REGIONAL_MANAGED_PROXY", "GLOBAL_MANAGED_PROXY") {
					results.Add(
						"Subnetwork does not have VPC flow logs enabled.",
						subnetwork.EnableFlowLogs,
					)
				} else {
					results.AddPassed(&subnetwork)
				}
			}
		}
		return
	},
)
