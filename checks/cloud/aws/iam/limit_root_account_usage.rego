# METADATA
# title: The "root" account has unrestricted access to all resources in the AWS account. It is highly recommended that the use of this account be avoided.
# description: |
#   The root user has unrestricted access to all services and resources in an AWS account. We highly recommend that you avoid using the root user for daily tasks. Minimizing the use of the root user and adopting the principle of least privilege for access management reduce the risk of accidental changes and unintended disclosure of highly privileged credentials.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html
# custom:
#   id: AVD-AWS-0140
#   avd_id: AVD-AWS-0140
#   provider: aws
#   service: iam
#   severity: LOW
#   short_code: limit-root-account-usage
#   recommended_action: Use lower privileged accounts instead, so only required privileges are available.
#   frameworks:
#     default:
#       - null
#     cis-aws-1.2:
#       - "1.1"
#     cis-aws-1.4:
#       - "1.7"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
package builtin.aws.iam.aws0140

import rego.v1

import data.lib.aws.iam
import data.lib.datetime

deny contains res if {
	some user in input.aws.iam.users
	iam.is_root_user(user)
	datetime.time_diff_lt_days(user.lastaccess.value, 1)
	res := result.new("The root user logged in within the last 24 hours", user)
}
