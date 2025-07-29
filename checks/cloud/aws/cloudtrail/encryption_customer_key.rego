# METADATA
# title: CloudTrail should use Customer managed keys to encrypt the logs
# description: |
#  Using AWS managed keys does not allow for fine grained control.  Using Customer managed keys provides comprehensive control over cryptographic keys, enabling management of policies, permissions, and rotation, thus enhancing security and compliance measures for sensitive data and systems.
# scope: package
# schemas:
#   - input: schema["cloud"]
# related_resources:
#   - https://docs.aws.amazon.com/awscloudtrail/latest/userguide/encrypting-cloudtrail-log-files-with-aws-kms.html
#   - https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#key-mgmt
# custom:
#   id: AVD-AWS-0015
#   avd_id: AVD-AWS-0015
#   provider: aws
#   service: cloudtrail
#   severity: HIGH
#   short_code: encryption-customer-managed-key
#   recommended_action: Use Customer managed key
#   input:
#     selector:
#       - type: cloud
#         subtypes:
#           - service: cloudtrail
#             provider: aws
#   examples: checks/cloud/aws/cloudtrail/encryption_customer_key.yaml
package builtin.aws.cloudtrail.aws0015

import rego.v1

import data.lib.cloud.metadata
import data.lib.cloud.value

deny contains res if {
	some trail in input.aws.cloudtrail.trails
	without_cmk(trail)
	res := result.new(
		"CloudTrail does not use a customer managed key to encrypt the logs.",
		metadata.obj_by_path(trail, ["kmskeyid"]),
	)
}

without_cmk(trail) if value.is_empty(trail.kmskeyid)

without_cmk(trail) if not trail.kmskeyid
