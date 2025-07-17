# METADATA
# title: Ensure resources have required tags
# description: |
#   Ensure that all resources in the CloudFormation template have the required tags such as "Environment" and "Owner".
#   These tags help in resource tracking, management, and categorization, making it easier to automate processes
#   and manage AWS infrastructure.
# scope: package
# related_resources:
#   - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/working-with-templates.html
# custom:
#   id: USR-CF-0001
#   avd_id: USR-CF-0001
#   severity: MEDIUM
#   short_code: ensure-required-tags
#   recommended_action: Ensure all resources are tagged with the appropriate metadata tags to facilitate resource management.
#   input:
#     selector:
#       - type: json
package user.cf.ensure_required_tags

import data.required_tags

import rego.v1

deny contains res if {
	some resource in input.Resources
	not resource.Tags
	res := result.new(
		sprintf("Resource %q does not have required tags %v", [resource.Type, required_tags]),
		{},
	)
}

deny contains res if {
	some resource in input.Resources
	some required_tag in required_tags
	not has_required_tag(resource.Tags, required_tag)
	res := result.new(
		sprintf("Resource %q does not have the required %q tag", [resource.Type, required_tag]),
		{},
	)
}

# Helper function to check if the tag exists
has_required_tag(tags, tag_name) if {
	some tag in tags
	tag.Key == tag_name
}
