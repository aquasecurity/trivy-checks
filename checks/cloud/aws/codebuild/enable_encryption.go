package codebuild

import (
	"github.com/aquasecurity/trivy-checks/pkg/rules"
	"github.com/aquasecurity/trivy/pkg/iac/providers"
	"github.com/aquasecurity/trivy/pkg/iac/scan"
	"github.com/aquasecurity/trivy/pkg/iac/severity"
	"github.com/aquasecurity/trivy/pkg/iac/state"
)

var CheckEnableEncryption = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AWS-0018",
		Provider:    providers.AWSProvider,
		Service:     "codebuild",
		ShortCode:   "enable-encryption",
		Summary:     "CodeBuild Project artifacts encryption should not be disabled",
		Impact:      "CodeBuild project artifacts are unencrypted",
		Resolution:  "Enable encryption for CodeBuild project artifacts",
		Explanation: `All artifacts produced by your CodeBuild project pipeline should always be encrypted`,
		Links: []string{
			"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codebuild-project-artifacts.html",
			"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codebuild-project.html",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformEnableEncryptionGoodExamples,
			BadExamples:         terraformEnableEncryptionBadExamples,
			Links:               terraformEnableEncryptionLinks,
			RemediationMarkdown: terraformEnableEncryptionRemediationMarkdown,
		},
		CloudFormation: &scan.EngineMetadata{
			GoodExamples:        cloudFormationEnableEncryptionGoodExamples,
			BadExamples:         cloudFormationEnableEncryptionBadExamples,
			Links:               cloudFormationEnableEncryptionLinks,
			RemediationMarkdown: cloudFormationEnableEncryptionRemediationMarkdown,
		},
		Severity:   severity.High,
		Deprecated: true,
	},
	func(s *state.State) (results scan.Results) {
		for _, project := range s.AWS.CodeBuild.Projects {
			if project.ArtifactSettings.EncryptionEnabled.IsFalse() {
				results.Add(
					"Encryption is not enabled for project artifacts.",
					project.ArtifactSettings.EncryptionEnabled,
				)
			} else {
				results.AddPassed(&project)
			}

			for _, setting := range project.SecondaryArtifactSettings {
				if setting.EncryptionEnabled.IsFalse() {
					results.Add(
						"Encryption is not enabled for secondary project artifacts.",
						setting.EncryptionEnabled,
					)
				} else {
					results.AddPassed(&setting)
				}
			}

		}
		return
	},
)
