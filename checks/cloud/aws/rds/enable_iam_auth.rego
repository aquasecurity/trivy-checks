# METADATA
# title: "RDS IAM Database Authentication Disabled"
# description: "Ensure IAM Database Authentication is enabled for RDS database instances to manage database access"
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/neptune/latest/userguide/iam-auth.html
# custom:
#   id: AWS-0176
#   aliases:
#     - AVD-AWS-0176
#     - enable-iam-auth
#   long_id: aws-rds-enable-iam-auth
#   provider: aws
#   service: rds
#   severity: MEDIUM
#   recommended_action: "Modify the PostgreSQL and MySQL type RDS instances to enable IAM database authentication."
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: rds
#             provider: aws
package builtin.aws.rds.aws0176

import rego.v1

deny contains res if {
	instance := input.aws.rds.instances[_]
	instance.engine.value == ["postgres", "mysql"][_]
	not instance.iamauthenabled.value
	res := result.new("Instance does not have IAM Authentication enabled", instance.iamauthenabled)
}
