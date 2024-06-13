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
#   terraform:
#     links:
#       - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/cloudtrail#kms_key_id
#     good_examples: checks/cloud/aws/cloudtrail/encryption_customer_key.tf.go
#     bad_examples: checks/cloud/aws/cloudtrail/encryption_customer_key.tf.go
#   cloudformation:
#     links:
#       - https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudtrail-trail.html#cfn-cloudtrail-trail-kmskeyid
#     good_examples: checks/cloud/aws/cloudtrail/encryption_customer_key.cf.go
#     bad_examples: checks/cloud/aws/cloudtrail/encryption_customer_key.cf.go
package builtin.aws.cloudtrail.aws0015

import rego.v1

deny contains res if {
	some trail in input.aws.cloudtrail.trails
	trail.kmskeyid.value == ""
	res := result.new("CloudTrail does not use a customer managed key to encrypt the logs.", trail.kmskeyid)
}
