# METADATA
# title: AWS required resource tags
# description: Ensure required tags are set on AWS resources
# scope: package
# schemas:
#   - input: schema["terraform-raw"]
# custom:
#   id:  USR-TFRAW-0001
#   avd_id:  USR-TFRAW-0001
#   severity: CRITICAL
#   short_code: required-aws-resource-tags
#   recommended_actions: "Add the required tags to AWS resources."
#   input:
#     selector:
#     - type: terraform-raw
package user.terraform.required_aws_tags

import rego.v1

resource_types_to_check := {"aws_s3_bucket"}

resources_to_check := {block |
	some module in input.modules
	some block in module.blocks
	block.kind == "resource"
	block.type in resource_types_to_check
}

required_tags := {"Access", "Owner"}

deny contains res if {
	some block in resources_to_check
	not block.attributes.tags
	res := result.new(
		sprintf("The resource %q does not contain the following required tags: %v", [block.type, required_tags]),
		block,
	)
}

deny contains res if {
	some block in resources_to_check
	tags_attr := block.attributes.tags
	tags := object.keys(tags_attr.value)
	missing_tags := required_tags - tags
	count(missing_tags) > 0
	res := result.new(
		sprintf("The resource %q does not contain the following required tags: %v", [block.type, missing_tags]),
		tags_attr,
	)
}
