# METADATA
# title: "RDS Deletion Protection Disabled"
# description: "Ensure deletion protection is enabled for RDS database instances."
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://aws.amazon.com/about-aws/whats-new/2018/09/amazon-rds-now-provides-database-deletion-protection/
# custom:
#   id: AWS-0177
#   aliases:
#     - AVD-AWS-0177
#     - enable-deletion-protection
#   long_id: aws-rds-enable-deletion-protection
#   provider: aws
#   service: rds
#   severity: MEDIUM
#   recommended_action: "Modify the RDS instances to enable deletion protection."
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: rds
#             provider: aws
package builtin.aws.rds.aws0177

import rego.v1

deny contains res if {
	instance := input.aws.rds.instances[_]
	not instance.deletionprotection.value
	res := result.new("Instance does not have Deletion Protection enabled", instance.deletionprotection)
}
