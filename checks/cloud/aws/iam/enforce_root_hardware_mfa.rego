# METADATA
# title: The "root" account has unrestricted access to all resources in the AWS account. It is highly recommended that this account have hardware MFA enabled.
# description: |
#   Hardware MFA adds an extra layer of protection on top of a user name and password. With MFA enabled, when a user signs in to an AWS website, they're prompted for their user name and password and for an authentication code from their AWS MFA device.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_physical.html
# custom:
#   id: AVD-AWS-0165
#   avd_id: AVD-AWS-0165
#   provider: aws
#   service: iam
#   severity: MEDIUM
#   short_code: enforce-root-hardware-mfa
#   recommended_action: Enable hardware MFA on the root user account.
#   frameworks:
#     cis-aws-1.4:
#       - "1.6"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
package builtin.aws.iam.aws0165

import rego.v1

deny contains res if {
	some user in input.aws.iam.users
	user.name.value == "root"
	not is_user_have_hardware_mfa(user)
	res := result.new("Root user does not have a hardware MFA device", user)
}

# is_user_have_hardware_mfa(user) if

is_user_have_hardware_mfa(user) if {
	some device in user.mfadevices
	device.isvirtual.value == false
}
