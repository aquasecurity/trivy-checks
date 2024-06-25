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
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/codebuild_project#encryption_disabled
#     good_examples: checks/cloud/aws/codebuild/enable_encryption.tf.go
#     bad_examples: checks/cloud/aws/codebuild/enable_encryption.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/codebuild/enable_encryption.cf.go
#     bad_examples: checks/cloud/aws/codebuild/enable_encryption.cf.go
package builtin.aws.codebuild.aws0018

import rego.v1

deny contains res if {
	some project in input.aws.codebuild.projects
	encryptionenabled := project.artifactsettings.encryptionenabled
	not encryptionenabled.value
	res := result.new("Encryption is not enabled for project artifacts.", encryptionenabled)
}

deny contains res if {
	some project in input.aws.codebuild.projects
	some setting in project.secondaryartifactsettings
	not setting.encryptionenabled.value
	res := result.new("Encryption is not enabled for secondary project artifacts.", setting.encryptionenabled)
}
