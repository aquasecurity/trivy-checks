# METADATA
# title: Missing description for security group/security group rule.
# description: |
#   Security groups and security group rules should include a description for auditing purposes.
#   Simplifies auditing, debugging, and managing security groups.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/AmazonElastiCache/latest/mem-ug/SecurityGroups.Creating.html
# custom:
#   id: AVD-AWS-0049
#   avd_id: AVD-AWS-0049
#   provider: aws
#   service: elasticache
#   severity: LOW
#   short_code: add-description-for-security-group
#   recommended_action: Add descriptions for all security groups and rules
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: elasticache
#             provider: aws
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticache_security_group#description
#     good_examples: checks/cloud/aws/elasticache/add_description_for_security_group.tf.go
#     bad_examples: checks/cloud/aws/elasticache/add_description_for_security_group.tf.go
#   cloudformation:
#     good_examples: checks/cloud/aws/elasticache/add_description_for_security_group.cf.go
#     bad_examples: checks/cloud/aws/elasticache/add_description_for_security_group.cf.go
package builtin.aws.elasticache.aws0049

import rego.v1

deny contains res if {
	some secgroup in input.aws.elasticache.securitygroups
	secgroup.description.value == ""
	res := result.new("Security group does not have a description.", secgroup.description)
}
