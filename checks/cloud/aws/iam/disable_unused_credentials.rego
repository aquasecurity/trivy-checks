# METADATA
# title: Credentials which are no longer used should be disabled.
# description: |
#   CIS recommends that you remove or deactivate all credentials that have been unused in 90 days or more. Disabling or removing unnecessary credentials reduces the window of opportunity for credentials associated with a compromised or abandoned account to be used.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://console.aws.amazon.com/iam/
# custom:
#   id: AVD-AWS-0144
#   avd_id: AVD-AWS-0144
#   provider: aws
#   service: iam
#   severity: MEDIUM
#   short_code: disable-unused-credentials
#   recommended_action: Disable credentials which are no longer used.
#   frameworks:
#     cis-aws-1.2:
#       - "1.3"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
package builtin.aws.iam.aws0144

import rego.v1

import data.lib.aws.iam

days_to_check = 90

deny contains res if {
	some user in input.aws.iam.users
	iam.user_is_inactive(user, days_to_check)
	res := result.new("User has not logged in for >90 days.", user)
}

deny contains res if {
	some user in input.aws.iam.users
	not iam.user_is_inactive(user, days_to_check)
	some key in user.accesskeys
	iam.key_is_unused(key, days_to_check)
	res := result.new(sprintf("User access key %q has not been used in >90 days", [key.accesskeyid.value]), user)
}
