# METADATA
# title: Missing description for security group/security group rule.
# description: |
#   Security groups and security group rules should include a description for auditing purposes.
#   Simplifies auditing, debugging, and managing security groups.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://www.cloudconformity.com/knowledge-base/aws/EC2/security-group-rules-description.html
# custom:
#   id: AVD-AWS-0083
#   avd_id: AVD-AWS-0083
#   provider: aws
#   service: redshift
#   severity: LOW
#   short_code: add-description-to-security-group
#   recommended_action: Add descriptions for all security groups and rules
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: redshift
#             provider: aws
#   cloudformation:
#     good_examples: checks/cloud/aws/redshift/add_description_to_security_group.cf.go
#     bad_examples: checks/cloud/aws/redshift/add_description_to_security_group.cf.go
package builtin.aws.redshift.aws0083

import rego.v1

deny contains res if {
	some group in input.aws.redshift.securitygroups
	not has_description(group)
	res := result.new(
		"Security group has no description.",
		object.get(group, "description", group),
	)
}

has_description(group) if group.description.value != ""
