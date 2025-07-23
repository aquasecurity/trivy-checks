# METADATA
# title: ASG desires too much capacity
# description: |
#   This check ensures that an AWS Auto Scaling Group (ASG) does not request an excessively large desired capacity.
#   A high desired capacity may lead to unnecessary costs and potential scaling issues.
#
#   Ensure that the desired capacity for Auto Scaling Groups is set to a reasonable value, typically within limits defined by your organization.
# scope: package
# related_resources:
#   - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/autoscaling_group
# custom:
#   id: USR-TFPLAN-0001
#   avd_id: USR-TFPLAN-0001
#   severity: MEDIUM
#   short_code: asg-too-much-capacity
#   recommended_action: Reduce the desired capacity of the Auto Scaling Group to an appropriate value.
#   input:
#     selector:
#       - type: json
package user.terraform.asg_capacity_check

import rego.v1

deny contains res if {
	some resource in input.planned_values.root_module.resources
	resource.type == "aws_autoscaling_group"
	resource.values.desired_capacity > 10

	res := result.new(
		sprintf("ASG $q desires too much capacity: %d.", [resource.name, resource.values.desired_capacity]),
		{},
	)
}
