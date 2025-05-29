# METADATA
# title: Resources should have required tags
# schemas:
# - input: schema["terraform-raw"]
# related_resources:
# - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/guides/resource-tagging
# custom:
#   id: USR-TF-0001
#   avd_id: USR-TF-0001
#   short_code: required-tags
#   severity: MEDIUM
#   input:
#     selector:
#     - type: terraform-raw
package user.tf.required_tags

import rego.v1

required_tags := {"Environment", "Owner", "Project"}

resources_to_check := {"aws_s3_bucket"}

deny contains res if {
	some block in input.modules[_].blocks
	block.kind == "resource"
	block.type in resources_to_check
	tags := block.attributes.tags

	used_tags := {k | some k, _ in tags.value}
	missed_tags := required_tags - used_tags
	count(missed_tags) > 0
	res := result.new(
		sprintf("The resource %q is missing required tags: %v", [block.type, missed_tags]),
		tags,
	)
}
