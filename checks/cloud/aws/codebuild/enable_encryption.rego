# METADATA
# title: CodeBuild Project artifacts encryption should not be disabled
# description: |
#   All artifacts produced by your CodeBuild project pipeline should always be encrypted
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-codebuild-project-artifacts.html
#   - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-codebuild-project.html
# custom:
#   id: AVD-AWS-0018
#   avd_id: AVD-AWS-0018
#   provider: aws
#   service: codebuild
#   severity: HIGH
#   short_code: enable-encryption
#   recommended_action: Enable encryption for CodeBuild project artifacts
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: codebuild
#             provider: aws
#   examples: checks/cloud/aws/codebuild/enable_encryption.yaml
package builtin.aws.codebuild.aws0018

import rego.v1

import data.lib.cloud.metadata

deny contains res if {
	some project in input.aws.codebuild.projects
	not is_encryption_enabled(project.artifactsettings)
	res := result.new(
		"Encryption is not enabled for project artifacts.",
		metadata.obj_by_path(project, ["artifactsettings", "encryptionenabled"]),
	)
}

is_encryption_enabled(settings) if settings.encryptionenabled.value

deny contains res if {
	some project in input.aws.codebuild.projects
	some setting in project.secondaryartifactsettings
	not is_encryption_enabled(setting)
	res := result.new(
		"Encryption is not enabled for secondary project artifacts.",
		metadata.obj_by_path(setting, ["encryptionenabled"]),
	)
}
