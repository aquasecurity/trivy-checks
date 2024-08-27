# METADATA
# title: Disabling or removing unnecessary credentials will reduce the window of opportunity for credentials associated with a compromised or abandoned account to be used.
# description: |
#   AWS IAM users can access AWS resources using different types of credentials, such as passwords or access keys. It is recommended that all credentials that have been unused in45 or greater days be deactivated or removed.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://console.aws.amazon.com/iam/
# custom:
#   id: AVD-AWS-0166
#   avd_id: AVD-AWS-0166
#   provider: aws
#   service: iam
#   severity: LOW
#   short_code: disable-unused-credentials-45-days
#   recommended_action: Disable credentials which are no longer used.
#   frameworks:
#     cis-aws-1.4:
#       - "1.12"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
package builtin.aws.iam.aws0166

import rego.v1

import data.lib.aws.iam

days_to_check = 45

deny contains res if {
	some user in input.aws.iam.users
	iam.user_is_inactive(user, days_to_check)
	res := result.new("User has not logged in for >45 days.", user)
}

deny contains res if {
	some user in input.aws.iam.users
	not iam.user_is_inactive(user, days_to_check)
	some key in user.accesskeys
	iam.key_is_unused(key, days_to_check)
	res := result.new(sprintf("User access key %q has not been used in >45 days", [key.accesskeyid.value]), user)
}
