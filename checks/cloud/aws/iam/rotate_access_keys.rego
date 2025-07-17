# METADATA
# title: Access keys should be rotated at least every 90 days
# description: |
#   Regularly rotating your IAM credentials helps prevent a compromised set of IAM access keys from accessing components in your AWS account.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/automatically-rotate-iam-user-access-keys-at-scale-with-aws-organizations-and-aws-secrets-manager.html
# custom:
#   id: AVD-AWS-0146
#   avd_id: AVD-AWS-0146
#   provider: aws
#   service: iam
#   severity: LOW
#   short_code: rotate-access-keys
#   recommended_action: Rotate keys every 90 days or less
#   frameworks:
#     cis-aws-1.2:
#       - "1.4"
#     cis-aws-1.4:
#       - "1.14"
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: iam
#             provider: aws
package builtin.aws.iam.aws0146

import rego.v1

import data.lib.datetime

deny contains res if {
	some user in input.aws.iam.users
	some key in user.accesskeys
	key.active.value

	ns := time.parse_rfc3339_ns(key.creationdate.value)
	diff := time.now_ns() - ns
	diff > datetime.days_to_ns(90)
	days := ceil((diff - datetime.days_to_ns(90)) / datetime.ns_in_day)

	msg := sprintf("User access key %q should have been rotated %d day(s) ago", [key.accesskeyid.value, days])
	res := result.new(msg, user)
}
