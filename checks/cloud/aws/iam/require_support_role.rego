# METADATA
# title: Missing IAM Role to allow authorized users to manage incidents with AWS Support.
# description: |
#   By implementing least privilege for access control, an IAM Role will require an appropriate
#
#   IAM Policy to allow Support Center Access in order to manage Incidents with AWS Support.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://console.aws.amazon.com/iam/
# custom:
#   id: AVD-AWS-0169
#   avd_id: AVD-AWS-0169
#   provider: aws
#   service: iam
#   severity: LOW
#   short_code: require-support-role
#   recommended_action: Create an IAM role with the necessary permissions to manage incidents with AWS Support.
#   frameworks:
#     cis-aws-1.4:
#       - "1.17"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
package builtin.aws.iam.aws0169

import rego.v1

deny contains res if {
	some role in input.aws.iam.roles
	not has_iam_support_role(role)
	res := result.new("Missing IAM support role.", role)
}

has_iam_support_role(role) if {
	some policy in role.policies
	policy.builtin.value
	policy.name.value == "AWSSupportAccess"
}
