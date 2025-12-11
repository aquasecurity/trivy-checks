# METADATA
# title: The "root" account has unrestricted access to all resources in the AWS account. It is highly recommended that this account have MFA enabled.
# description: |
#   MFA adds an extra layer of protection on top of a user name and password. With MFA enabled, when a user signs in to an AWS website, they're prompted for their user name and password and for an authentication code from their AWS MFA device.
#
#   When you use virtual MFA for the root user, CIS recommends that the device used is not a personal device. Instead, use a dedicated mobile device (tablet or phone) that you manage to keep charged and secured independent of any individual personal devices. This lessens the risks of losing access to the MFA due to device loss, device trade-in, or if the individual owning the device is no longer employed at the company.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html#securityhub-cis-controls-1.14
# custom:
#   id: AVD-AWS-0142
#   avd_id: AVD-AWS-0142
#   provider: aws
#   service: iam
#   severity: CRITICAL
#   short_code: enforce-root-mfa
#   recommended_action: Enable MFA on the root user account.
#   frameworks:
#     cis-aws-1.4:
#       - "1.5"
#     cis-aws-1.2:
#       - "1.13"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
package builtin.aws.iam.aws0142

import rego.v1

import data.lib.aws.iam

deny contains res if {
	some user in input.aws.iam.users
	iam.is_root_user(user)
	not iam.user_has_mfa_devices(user)
	res := result.new("Root user does not have an MFA device", user)
}
