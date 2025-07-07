# METADATA
# title: The root user has complete access to all services and resources in an AWS account. AWS Access Keys provide programmatic access to a given account.
# description: |
#   CIS recommends that all access keys be associated with the root user be removed. Removing access keys associated with the root user limits vectors that the account can be compromised by. Removing the root user access keys also encourages the creation and use of role-based accounts that are least privileged.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
# custom:
#   id: AWS-0141
#   aliases:
#     - AVD-AWS-0141
#     - no-root-access-keys
#   long_id: aws-iam-no-root-access-keys
#   provider: aws
#   service: iam
#   severity: CRITICAL
#   recommended_action: Use lower privileged accounts instead, so only required privileges are available.
#   frameworks:
#     default:
#       - null
#     cis-aws-1.2:
#       - "1.12"
#     cis-aws-1.4:
#       - "1.4"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
#   examples: checks/cloud/aws/iam/no_root_access_keys.yaml
package builtin.aws.iam.aws0141

import rego.v1

import data.lib.aws.iam

deny contains res if {
	some user in input.aws.iam.users
	iam.is_root_user(user)

	some key in user.accesskeys
	key.active.value

	res := result.new("Access key exists for root user", key)
}
