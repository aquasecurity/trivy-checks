package athena

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckNoEncryptionOverride = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0007",
		Provider:    providers.AWSProvider,
		Service:     "athena",
		ShortCode:   "no-encryption-override",
		Summary:     "Athena workgroups should enforce configuration to prevent client disabling encryption",
		Impact:      "Clients can ignore encryption requirements",
		Resolution:  "Enforce the configuration to prevent client overrides",
		Explanation: `Athena workgroup configuration should be enforced to prevent client side changes to disable encryption settings.`,
		Links: []string{
			"https://docs.aws.amazon.com/athena/latest/ug/manage-queries-control-costs-with-workgroups.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformNoEncryptionOverrideGoodExamples,
			BadExamples:         terraformNoEncryptionOverrideBadExamples,
			Links:               terraformNoEncryptionOverrideLinks,
			RemediationMarkdown: terraformNoEncryptionOverrideRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationNoEncryptionOverrideGoodExamples,
			BadExamples:         cloudFormationNoEncryptionOverrideBadExamples,
			Links:               cloudFormationNoEncryptionOverrideLinks,
			RemediationMarkdown: cloudFormationNoEncryptionOverrideRemediationMarkdown,
		},
		Severity:   severity.High,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, workgroup := range s.AWS.Athena.Workgroups {
			if workgroup.Metadata.IsUnmanaged() {
				continue
			}
			if workgroup.EnforceConfiguration.IsFalse() {
				results.Add(
					"The workgroup configuration is not enforced.",
					workgroup.EnforceConfiguration,
				)
			}
		}
		return
	},
)
